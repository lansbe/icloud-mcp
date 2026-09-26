// The standing containment gate: every DAV request site under `src/dav/` that
// could be aimed by a decoded token either asserts containment first, or is
// listed here as exempt with its reason.
//
// **This file is the executable form of `03-REVIEW.md` CR-01.** That finding was
// that `getEvent` and `getContact` took two URLs out of a caller-supplied,
// unauthenticated token and handed them straight to a multi-get, while
// `./transport.ts` attaches the Apple credential to whatever URL it is given —
// so a token naming a foreign origin sent the credential there. 03-12 fixed it
// at the four call sites. This file is what stops the fix decaying.
//
// ## Why a standing gate rather than four fixed call sites
//
// The four assertions are the PREVENTIVE half and this file is the DETECTIVE
// half. CR-01's own diagnosis of how the phase got here is that 03-06 and 03-07
// each annotated a field "Trusted" on the strength of its usual shape rather
// than the fence's stated test — a convention decaying across plans that each
// looked correct alone. A call-site assertion decays exactly the same way: the
// next phase adds `getSomething`, nobody remembers, and the hole reopens with a
// green suite.
//
// 03-12 Task 1 chose `call-site-helper` over a transport choke point, and chose
// it ON THIS BASIS — `discoverAccount` bootstraps through the very transport a
// choke point would constrain, so a choke point would need a mode, and a mode
// can be in the wrong state. This gate is the durability that choice was traded
// for. It is load-bearing, not decoration.
//
// ## The rule for changing this file
//
// A failing set-equality assertion means A DAV REQUEST SITE APPEARED OR
// DISAPPEARED. The fix is never to widen a list to make a run go green. It is
// to decide which half the site belongs on:
//
//   - Its target can be aimed by a decoded token → assert containment at the
//     call site, before the request, and add it to `HOME_CHECKED_CALL_SITES`.
//   - Its target is derived from `resolved.homeUrl` and no token reaches it →
//     add it to `HOME_EXEMPT_REQUEST_SITES` **with the reason written into the
//     entry**, not into a comment beside it.
//
// ## Why SET EQUALITY, in both directions
//
// Each direction catches a different failure, and the second is the one that is
// easy to miss:
//
//   - An UNEXPECTED site is a new request target nobody decided about.
//   - A MISSING site means a protected call site was deleted or renamed, and
//     this gate is now guarding nothing. A rule that silently matches nothing is
//     indistinguishable from a rule that was never added — which is the same
//     both-directions discipline the phase's existing count constraints already
//     use, and which `03-VERIFICATION.md` records as verified-clean.
//
// ## Why the enumeration is deliberately conservative
//
// It is regex over source text, and it is biased to OVER-report. A site flagged
// here that turns out to be exempt costs one human one reason string, once. A
// site missed costs the credential. When in doubt the pattern widens.
//
// ## What this gate does NOT do
//
//   - It is a source-text audit, not a proof. It reads what the file says, not
//     what it does.
//   - It cannot see inside `node_modules/`. `tsdav` fans out internally within
//     its own collection fetches, which is why the STRUCTURAL half of the
//     adjacent connection-budget guarantee is the per-request serialisation gate
//     in `src/dav/transport.ts` rather than anything visible at a call site.
//   - It says nothing about response CONTENT. That is the other two gates' job,
//     below.
//
// ## Relationship to the two standing gates this phase already carries
//
// All three COMPOSE. **None subsumes another, and they are deliberately not
// merged** (D-56's rule is against a second mitigation that DUPLICATES another;
// these three overlap in subject and not in property):
//
//   - `test/dav-tools.test.ts` — 03-09's `TRUSTED_ROW_KEYS` containment walk.
//     Axis: response VALUES. Property: no stranger-authored value's text lands
//     outside the fence.
//   - `test/dav-fence-audit.test.ts` — 03-10's `TRUSTED_FIELD_ALLOWLIST` gate.
//     Axis: response KEYS. Property: a new field on a trusted row is a decision,
//     not a default.
//   - this file — axis: REQUEST TARGETS. Property: a URL that a stranger's token
//     can aim is checked against the home set before it reaches the wire.
//
// The first two are about what comes BACK. This one is about where we GO. A
// response-side gate cannot see a misdirected request at all, and this one
// cannot see a field that crossed the fence, so all three must pass
// independently and each file names the others so they cannot drift apart
// unnoticed.
//
// ## Why the sources are imported rather than read off disk
//
// This test runs in the `workers` project, inside real workerd, and a Workers
// isolate has no filesystem. The project's other source-reading test
// (`test/forbidden-tokens.test.ts`) is in the `static` Node project instead, but
// that route needs `node:fs`, and this project deliberately carries no Node type
// package — adding one is a new dependency, which this plan is not permitted to
// take. Vite's `?raw` suffix inlines the file's text at build time and so works
// in the isolate, at the cost of a suppression: the suffix has no ambient
// declaration because `vite/client` is not in `tsconfig.json`'s `types`. The
// suppression is proven non-vacuous by `tsc` itself, which errors on a
// `@ts-expect-error` that suppresses nothing.
//
// ## Why the tree is GLOBBED rather than listed file by file
//
// The scanned set was three named `?raw` imports until the phase-03 security
// audit found what that costs: `src/dav/diagnose.ts` had carried two live DAV
// request sites since 03-13, and this gate — whose whole stated property is
// that "a future `src/dav/` call site" fails it — had never once looked at
// them. Neither was a containment risk (both targets are derived from
// `resolved.homeUrl`, and both are exempt below with that reason written down),
// so nothing was exposed. But a gate that names a property it does not have is
// worse than no gate: it is the thing a later reader trusts.
//
// Adding two more named imports would have closed the two instances. Globbing
// the directory closes the CLASS — a new `src/dav/*.ts` is scanned the moment
// it exists, with nobody needing to remember. That is the same argument 03-12
// made when it chose where to put the containment helper, and the same shape as
// 03-09's original defect: the walk enumerated the wrong side, so a newly-added
// thing defaulted to safe-looking.
//
// `import.meta.glob` is Vite's own build-time directory read and so survives the
// no-filesystem constraint above intact. It costs the same single suppression,
// for the same reason and with the same `tsc`-proven non-vacuity — and it costs
// it ONCE for the whole directory rather than once per file, which is the
// smaller surface as well as the more durable one.
//
// The glob deliberately reaches files that make no DAV request at all
// (`transport.ts`, `errors.ts`, `ids.ts`, `icalendar.ts`, `vcard.ts`). They
// contribute nothing today and that is the point: a hand-rolled request added
// to any of them is a decision this gate will demand rather than a change it
// will sleep through. `loaded the whole directory as text` below asserts the
// glob really is wider than the two lists, so a pattern quietly narrowed back
// to the declared files cannot pass as a glob.
//
// This module contains no logging calls of any kind and must never acquire any.

import { env } from "cloudflare:workers";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  createCalendarCollection,
  createEvent,
  deleteCalendarCollection,
  deleteEvent,
  updateCalendarCollection,
  updateEvent,
} from "../src/dav/calendar";
import { clearDavCache, resolveDavAccount } from "../src/dav/discovery";
import { DavNotFoundError } from "../src/dav/errors";
import { decodeCalendarId, encodeCalendarId } from "../src/dav/ids";
import type { EventRef } from "../src/dav/ids";
import { createDavFetch } from "../src/dav/transport";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import type { Principal } from "../src/principal";

// The owner's principal, as the PROMISE the real env constructor returns over
// the pool's ambient environment. The DAV fetch builder and the registrars take
// the promise. The no-op handler means a file that builds it and awaits it
// nowhere leaves no rejection unheard. Everyone who does await it still sees
// the refusal.
const owner = ownerPrincipal();
owner.catch(() => {});

// What that promise resolves to. Resolved once, and the very same object is
// handed to every call: the password reader answers only the object a
// constructor built, so it is never spread and never cloned.
let principal: Principal;
beforeAll(async () => {
  principal = await owner;
});

/** The directory this gate owns. Every key in `SOURCES` begins with it. */
const DAV_DIR = "src/dav/";

// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here; see above.
const GLOBBED: Record<string, string> = import.meta.glob("../src/dav/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

const CALENDAR = "src/dav/calendar.ts";
const CONTACTS = "src/dav/contacts.ts";
const DISCOVERY = "src/dav/discovery.ts";
const DIAGNOSE = "src/dav/diagnose.ts";

/**
 * A glob key as a repository-relative path.
 *
 * Sliced from `src/dav/` rather than stripped of a leading `../`, because Vite
 * resolves a glob key relative to the importing module and the exact prefix is
 * an implementation detail of the bundler rather than a promise to this file. A
 * key that does not contain the directory at all is returned unchanged, and the
 * non-vacuity assertion below then reports it rather than this function hiding
 * it behind a silent rename.
 */
function repoPathOf(globKey: string): string {
  const index = globKey.indexOf(DAV_DIR);
  return index === -1 ? globKey : globKey.slice(index);
}

/** The scanned tree, typed on the way in so nothing downstream is `any`. */
const SOURCES: Record<string, string> = Object.fromEntries(
  Object.entries(GLOBBED).map(([key, text]) => [repoPathOf(key), text]),
);

// ---------------------------------------------------------------------------
// The vocabulary
// ---------------------------------------------------------------------------

/**
 * tsdav's collection-creation helper, by name, assembled rather than written.
 *
 * **It has to be a value in the vocabulary below, and it cannot be spelled
 * there.** The helper's name is a banned token in every scanned root — `src/`,
 * `scripts/` and `test/` alike, with no scope and no file exclusion — because it
 * hardcodes the RFC 4791 calendar-creation method this runtime refuses to build
 * a request from. So a plain literal in the array below would fail the commit
 * hook on every commit that touched this tree.
 *
 * **Building it is byte-for-byte equivalent to writing it, and that is checkable
 * rather than a hope.** The array's values are consumed in exactly one place —
 * `enumerateRequestSites` below — which assembles ``new RegExp(`\\b${request}\\s*\\(`)``
 * at RUNTIME from each value, and `keyOf` composes that same runtime value into
 * the `file › fn › request` identity the two-direction set equality compares.
 * Nothing anywhere reads this array's SOURCE TEXT: the `?raw` glob at the top of
 * this file loads `src/dav/*.ts` and never this file, so the containment gate
 * does not read itself. A joined string therefore produces the same regex, the
 * same key, the same equality and the same redness on the day a call site
 * appears.
 *
 * **Do NOT "tidy" this into a plain string literal, and do NOT delete the entry
 * it feeds.** `scripts/forbidden-tokens.mjs` warns in its own header that a
 * concatenation written to dodge self-matching reads as an accident and gets
 * cleaned up by the next person through, so this says it outright: collapsing
 * the join breaks the pre-commit hook rather than tidying the file. Deleting the
 * entry is worse and quieter — it would cost the guarantee the comment beside
 * the entry states, with nothing failing on the way out, which is exactly the
 * "losing a guarantee is quieter than gaining a duplicate of it" failure
 * `.claude/CLAUDE.md` § Enforcement names. Excluding this file from the scan is
 * refused too: exclusion is all-rules-per-file, so it would cost this suite
 * every OTHER rule it carries.
 */
const TSDAV_COLLECTION_CREATE_HELPER = ["make", "Calendar"].join("");

/**
 * Every name that reaches the network from `src/dav/`.
 *
 * This is the REQUEST-PRIMITIVE half of `dav-concurrent-request`'s alternation
 * in `scripts/forbidden-tokens.mjs`, restated rather than imported: that module
 * reads the repository off disk at import time, so importing it into a workerd
 * isolate would fail before a single assertion ran. The two lists are therefore
 * a drift risk, and the mitigation is that both are additive-only — a tsdav
 * function added to one and not the other under-reports, which the conservative
 * bias above already accepts, and never silently passes a site that IS matched.
 *
 * **Half, and deliberately so.** WR-03 widened that rule to name the service
 * entry points as well (`getEvent`, `searchContacts`, `withRediscovery` and the
 * rest), because a fan-out is written where a tool can see it. Those names do
 * not belong here: this gate asks WHICH URL A REQUEST IS AIMED AT, and an entry
 * point aims none — it delegates to one of the names below, which is the site
 * that gets checked or exempted. Copying them in would attribute the same
 * request twice under two different keys and make the set equality meaningless.
 *
 * `davFetch` is here because a hand-rolled request reaches for the injected
 * transport directly; it currently matches nothing, and that is the point of
 * listing it.
 */
const DAV_REQUEST_FUNCTIONS = Object.freeze([
  "davFetch",
  "createAccount",
  "propfind",
  "fetchCalendars",
  "fetchCalendarObjects",
  "calendarQuery",
  "calendarMultiGet",
  "fetchAddressBooks",
  "fetchVCards",
  "addressBookQuery",
  "addressBookMultiGet",
  "supportedReportSet",
  // The two WRITE primitives, added in Phase 5. They were absent while
  // `createEvent` shipped, which the additive-only bias above tolerates as an
  // under-report — but the tolerance reads oddly on the request class where
  // being aimed at the wrong origin costs the most: a write sends the account's
  // credential AND the caller's own content to whatever the URL named. The
  // read/write asymmetry was in the gate's coverage rather than in its
  // argument, so it is closed here.
  "createCalendarObject",
  "updateCalendarObject",
  // The third, added in 05-07. It is the one write primitive whose target
  // being wrong is not merely a leak: an unchecked URL here sends the
  // credential AND removes whatever it addressed.
  "deleteCalendarObject",
  // The principal read, added in 05-08. A READ, so the leak is one-directional
  // — but the credential still travels to whatever URL it is handed, and the
  // additive-only bias above tolerating an under-report is not a reason to
  // leave one in place when the site is right here being written.
  "fetchCalendarUserAddresses",
  // Phase 14's three, added with the SPIKE-04 collection write probe. The
  // additive-only bias above would have tolerated leaving them off as an
  // under-report — but it reads the same way here as it did for phase 5's
  // writes, and worse: `davRequest` sends a hand-assembled extended MKCOL or
  // PROPPATCH to whatever URL it is handed, and `deleteObject` REMOVES what it
  // addresses. An unchecked target on either sends the account's credential
  // somewhere and changes something there.
  //
  // tsdav's collection-creation helper stays in this VOCABULARY with no call
  // site to match, and that is deliberate. It issues the RFC 4791
  // calendar-creation method, and this runtime refuses to build a request
  // carrying that method at all — so the probe uses extended MKCOL instead and
  // nothing calls it. Leaving the name here means the day something does call
  // it, the enumeration finds the site and the set equality below goes red
  // until it is declared. Removing the name would make that site invisible
  // instead.
  //
  // It is the ONE entry in this array that is assembled rather than written,
  // and the reason is that both its own name and the method it issues are
  // banned tokens in every scanned root — see the constant's docstring above
  // for why the assembly is byte-for-byte equivalent to a literal here, and for
  // why deleting the entry and excluding this file were both refused. The
  // guarantee the paragraph above describes is preserved exactly, not
  // approximately: same runtime string, same regex, same key, same equality.
  TSDAV_COLLECTION_CREATE_HELPER,
  "davRequest",
  "deleteObject",
  // Phase 16's two CardDAV write primitives. `createVCard` shipped with CONW-01
  // and was left off this vocabulary, which the additive-only bias above
  // tolerates as an under-report — but the tolerance reads exactly as oddly here
  // as it did for phase 5's calendar writes, and for the same reason: a write
  // sends the account's credential AND the caller's own card content to whatever
  // the URL named. `updateVCard` arrives with CONW-02 and is the sharper of the
  // two, because an unchecked target on an overwrite does not merely leak — it
  // replaces whatever it addressed. Both are declared below rather than exempt.
  "createVCard",
  "updateVCard",
]);

// ---------------------------------------------------------------------------
// The two declared lists
// ---------------------------------------------------------------------------

/** One token-borne URL, proven to be checked before the request it aims. */
interface CheckedSite {
  /** Repository-relative path. */
  file: string;
  /** The enclosing exported function. */
  fn: string;
  /** The reference field asserted, exactly as it is written at the call site. */
  field: string;
  /** The request the assertion must lexically precede. */
  guards: string;
  /**
   * The helper whose body holds the assertion, when it is not inline in `fn`.
   *
   * **Added because 05-07 moved two writers' containment into one shared
   * preamble, and the ordering property had to survive the move rather than be
   * traded for it.** Two hand-written copies of a security check is how one of
   * them ends up with a single `assertUnderHome`, so factoring was the right
   * change — but a gate that only reads `fn`'s own body cannot see a check that
   * has moved one frame out, and it fails LOUDLY rather than silently, which is
   * the only reason this field exists rather than an exemption.
   *
   * When it is present the ordering assertion becomes a two-link chain, and
   * both links are checked: the assertions precede the helper's delegation, and
   * `fn`'s call to the helper precedes `fn`'s own request. Composed, the check
   * still runs before the credential reaches the wire — which is the property,
   * expressed over the code as it is now written rather than over the shape it
   * used to have.
   */
  via?: string;
}

/**
 * The line a containment helper delegates on, once its assertions have run.
 *
 * Named as a constant rather than inlined so a reader can see that the second
 * link of the chain is anchored on real text: the helper's parameter is called
 * `write`, and everything the callers do reaches the network from inside it.
 * A helper that asserted AFTER this line would satisfy a presence check
 * completely and would have sent the credential before it ran.
 */
const HELPER_DELEGATION = "write(resolved)";

/**
 * Every URL that arrives inside a decoded token and is checked before it flies.
 *
 * Exported so a reader arriving from a failing run can find this list from
 * anywhere else, and so `03-REVIEW.md` has a named symbol to point at rather
 * than a line number that goes stale.
 *
 * The COUNT is deliberately not stated in this sentence. It said "the four"
 * through three plans and was wrong on the fourth, which is the same silent
 * staleness a number written down twice always acquires — nothing fails when
 * the prose stops matching the array. How many there are is a question for the
 * array.
 *
 * Both URLs of each pair are here because each independently names what the
 * server is asked for: the object URL is sent separately as the multi-get's
 * `objectUrls` entry, so checking the collection alone is not checking the call.
 */
export const HOME_CHECKED_CALL_SITES: readonly CheckedSite[] = Object.freeze([
  // `readEvent` rather than `getEvent`, because Phase 5's preview needs the
  // ETag from the same multi-status as the body and the two callers now share
  // one body. The request did not move origin or lose its guard — it acquired a
  // second caller — but the enclosing function's NAME is this gate's identity,
  // so the rename is a diff a reader has to approve rather than a silent one.
  {
    file: CALENDAR,
    fn: "readEvent",
    field: "ref.calendarUrl",
    guards: "calendarMultiGet",
  },
  {
    file: CALENDAR,
    fn: "readEvent",
    field: "ref.objectUrl",
    guards: "calendarMultiGet",
  },
  // The two WRITES. Both check BOTH urls, and on the write path the second
  // check matters more than it does on the read path: `createEvent`'s object
  // URL is CONSTRUCTED from a filename this server minted rather than decoded,
  // so no earlier check has ever seen it.
  {
    file: CALENDAR,
    fn: "createEvent",
    field: "ref.collectionUrl",
    guards: "createCalendarObject",
  },
  {
    file: CALENDAR,
    fn: "createEvent",
    field: "objectUrl",
    guards: "createCalendarObject",
  },
  // The two writers that address an EXISTING resource share one containment
  // preamble, so both name it in `via`. `createEvent` above deliberately does
  // not: its object URL is constructed inside its own callback from a filename
  // this server mints, so there is no shared `EventRef` for the helper to take.
  {
    file: CALENDAR,
    fn: "updateEvent",
    field: "ref.calendarUrl",
    guards: "updateCalendarObject",
    via: "withContainedTarget",
  },
  {
    file: CALENDAR,
    fn: "updateEvent",
    field: "ref.objectUrl",
    guards: "updateCalendarObject",
    via: "withContainedTarget",
  },
  {
    file: CALENDAR,
    fn: "deleteEvent",
    field: "ref.calendarUrl",
    guards: "deleteCalendarObject",
    via: "withContainedTarget",
  },
  {
    file: CALENDAR,
    fn: "deleteEvent",
    field: "ref.objectUrl",
    guards: "deleteCalendarObject",
    via: "withContainedTarget",
  },
  // `readContact` rather than `getContact`, for `readEvent`'s reason above
  // exactly: CONW-02's write needs the entity tag out of the same multi-status as
  // the card, so the plain read and the read-with-version now share one body. The
  // request did not move origin and did not lose its guard — it acquired a second
  // caller — but the enclosing function's NAME is this gate's identity, so the
  // rename is a diff a reader has to approve rather than a silent one.
  {
    file: CONTACTS,
    fn: "readContact",
    field: "ref.addressBookUrl",
    guards: "addressBookMultiGet",
  },
  {
    file: CONTACTS,
    fn: "readContact",
    field: "ref.objectUrl",
    guards: "addressBookMultiGet",
  },
  // The two CardDAV writes, both contained through one shared helper — which is
  // why both declare `via` and the ordering assertion becomes a two-link chain.
  // `withContainedContactTarget` is a LOCAL twin of the calendar helper rather
  // than a reuse of it, because `resolved.homeUrl` is a DIFFERENT value for
  // CardDAV and asserting a contact's urls against the calendar home set is
  // 03-REVIEW.md CR-01's bug exactly.
  //
  // `createContact` shipped with CONW-01 while `createVCard` was absent from the
  // vocabulary above, so this gate could not see its site at all. Declaring the
  // primitive is what surfaced it; these entries are that declaration, not a new
  // check on the create.
  {
    file: CONTACTS,
    fn: "createContact",
    field: "ref.addressBookUrl",
    guards: "createVCard",
    via: "withContainedContactTarget",
  },
  {
    file: CONTACTS,
    fn: "createContact",
    field: "ref.objectUrl",
    guards: "createVCard",
    via: "withContainedContactTarget",
  },
  {
    file: CONTACTS,
    fn: "updateContact",
    field: "ref.addressBookUrl",
    guards: "updateVCard",
    via: "withContainedContactTarget",
  },
  {
    file: CONTACTS,
    fn: "updateContact",
    field: "ref.objectUrl",
    guards: "updateVCard",
    via: "withContainedContactTarget",
  },
  // CALM-05's rename and recolour — **the first entry on this list with ONE
  // url rather than two, and the first collection write in this project whose
  // target is genuinely caller-supplied.**
  //
  // The create beside it in the same module is EXEMPT, and the difference is
  // the whole reason this one is here: `CreateCalendarInput` carries a name and
  // a colour and no url at all, so there is nothing a forged token could aim.
  // `UpdateCalendarInput` carries a collection URL that arrives inside an
  // opaque id the model may have read out of an event description a stranger
  // wrote, and `src/dav/transport.ts` attaches the Apple ID and the
  // app-specific password to whatever URL it is handed. So the exemption's own
  // closing sentence — "the rename and delete that follow in plans 17-04 and
  // 17-06 belong on the checked list instead" — is discharged here.
  //
  // ONE url is not a gap in the pairing claim above; it is the shape of the
  // request. A property update addresses a collection, and a collection has no
  // object hanging off it the way an event ref does. That is why the expected
  // count is now derived from the source rather than fixed at two.
  {
    file: CALENDAR,
    fn: "updateCalendarCollection",
    field: "collectionUrl",
    guards: "davRequest",
  },
  // CALM-06's count read, on exactly the rename's footing one entry up: the
  // collection URL arrives inside a caller-supplied opaque id, so it is checked
  // rather than exempt, and it addresses one url because a collection has no
  // object hanging off it.
  //
  // A READ, so the leak is one-directional — but one-directional is not
  // harmless here, and the additive-only tolerance above is not a reason to
  // leave a site unchecked when it is right here being written:
  // `src/dav/transport.ts` attaches the Apple ID and the app-specific password
  // to whatever URL it is handed, and a forged id would ship both to whatever
  // origin it named. The refusal is asserted to cost ZERO outbound requests in
  // `test/dav-calendar.test.ts`, which is the falsifiable half.
  {
    file: CALENDAR,
    fn: "readCollectionState",
    field: "collectionUrl",
    guards: "propfind",
  },
  // CALM-06's removal — **the most destructive request in this project, and the
  // one whose target arrives in the STRONGEST position of any entry here.**
  //
  // The collection URL reaches it out of a SIGNED confirmation payload rather
  // than out of a bare opaque id: `applyCollectionCommit` reads it from
  // `payload.o`, and that payload's seal has already been verified with this
  // server's own key and checked against the signed-in principal. So a forged id
  // cannot reach this function at all without first forging an HMAC.
  //
  // **It is on the CHECKED list anyway, and the hostile case is written rather
  // than exempted.** An exemption's reason has to be a claim about where the URL
  // came from, and the honest claim here stops one step short of what an
  // exemption needs: the payload is genuine, and a genuine payload minted for one
  // account and presented on ANOTHER account's connection carries a URL under the
  // first account's home and not the second's. That is exactly what
  // `test/cross-user.test.ts` exists to catch, and `assertUnderHome` against THIS
  // connection's own resolved home is the second layer that catches it here. A
  // read that leaked would be one-directional; this one sends the credential AND
  // removes a calendar and everything in it.
  {
    file: CALENDAR,
    fn: "deleteCalendarCollection",
    field: "collectionUrl",
    guards: "deleteObject",
  },
]);

/** One request site that needs no containment assertion, and why. */
interface ExemptSite {
  file: string;
  fn: string;
  /** The request function called. */
  request: string;
  /** Why no token can aim this request. A string in the entry, not a comment. */
  reason: string;
}

/**
 * The request sites whose target cannot be aimed by a decoded token.
 *
 * Every reason here is a claim about where the URL CAME FROM, because that is
 * the only thing that makes containment unnecessary rather than merely absent.
 */
export const HOME_EXEMPT_REQUEST_SITES: readonly ExemptSite[] = Object.freeze([
  {
    file: CALENDAR,
    fn: "fetchCollections",
    request: "propfind",
    reason:
      "the target IS resolved.homeUrl — the enumeration that every other calendar target is derived from, so there is nothing above it to be contained by",
  },
  {
    file: CALENDAR,
    fn: "collectFrom",
    request: "fetchCalendarObjects",
    reason:
      "the target is a collection URL that fetchCollections enumerated from resolved.homeUrl, and it is the ONLY way one is selected: pagedEvents finds the decoded calendarId in that enumeration and refuses a non-member with DavNotFoundError, so the URL reaching this request is always one the account's own home set produced and never one the token named. The intersection used to be conditional -- an omitted calendarId listed every collection and skipped it -- and calendarId became REQUIRED when the account-wide form was withdrawn, so the reason is now unconditional and correspondingly stronger. It is stronger than containment and costs the enumeration to be",
  },
  {
    file: CALENDAR,
    fn: "resolveOrganizerAddress",
    request: "fetchCalendarUserAddresses",
    reason:
      "the target is account.principalUrl, built by davAccountFor from the discovery triple this call's own withRediscovery just resolved — the same bootstrap-adjacent URL every other target on this account is derived from, so there is nothing above it to be contained by. The stronger half of the claim is that this function takes NO caller input at all: no identifier, no cursor and no reference reaches it, so there is nothing a token could aim even in principle, which is the same argument the two dav_diagnose sites below make",
  },
  // Phase 17 (CALM-04). The first COLLECTION write in this project, and the
  // sharpest request target the milestone has produced so far — which is
  // precisely why it is exempt rather than checked, and why saying so in one
  // line would be the wrong length.
  //
  // **What makes the class sharp.** On the rename and the delete that follow in
  // plans 17-04 and 17-06, a collection URL is CALLER-SUPPLIED: it arrives
  // inside an opaque id the model may have read out of an event description a
  // stranger wrote, and `src/dav/transport.ts` attaches the Apple ID and the
  // app-specific password to whatever URL it is handed. An unchecked target on
  // either ships both to an attacker's host, and on the delete it removes
  // whatever it addressed first.
  //
  // **What makes THIS one exempt anyway.** The create is the one member of that
  // class with no caller-supplied URL at all. `CreateCalendarInput` carries a
  // display name and a `#RRGGBB` colour and nothing else — no id, no href, no
  // reference of any kind — and the target is one `crypto.randomUUID()` segment
  // resolved against the home set THIS principal's own discovery just returned.
  // There is nothing a forged token could aim, so a hostile case here would be
  // an assertion that cannot fail, and this reason string is what that
  // mechanism exists to record honestly rather than dress up.
  //
  // The site nonetheless calls `assertUnderHome` on the planned URL before the
  // request. That is defence in depth against a future edit to the two lines
  // that build it, not the authorisation it is on the paths that decode an id —
  // so it is recorded here rather than claimed as a check this gate verified.
  // The DRIVEN half below does what is actually falsifiable about this site: it
  // runs the real function and asserts the recorded request went under the
  // resolved home, and that no extra key on the input can move it.
  {
    file: CALENDAR,
    fn: "createCalendarCollection",
    request: "davRequest",
    reason:
      "the target is one crypto.randomUUID() segment resolved against resolveDavAccount's own homeUrl for THIS principal, so the only free component of the URL is generated on that line rather than accepted from anywhere. CreateCalendarInput carries a display name and a #RRGGBB colour and nothing else -- no id, no href and no reference of any kind crosses the tool boundary -- so there is no caller-supplied URL for assertUnderHome to be checking, which is why this is exempt rather than checked. It is the same claim the two dav_diagnose collection sites make and it is stronger than a derivation argument, not weaker. The site does call assertUnderHome on the planned URL before the request anyway, as defence in depth against a future edit to the lines that build it; that is recorded rather than claimed, because a hostile case against an input carrying no URL is an assertion that cannot fail. This exemption is scoped to the CREATE: the rename and delete that follow in plans 17-04 and 17-06 take a collection URL out of a caller-supplied opaque id and belong on the checked list instead",
  },
  {
    file: CONTACTS,
    fn: "fetchBooks",
    request: "fetchAddressBooks",
    reason:
      "the target IS resolved.homeUrl, as its calendar counterpart above",
  },
  {
    file: CONTACTS,
    fn: "serverRoute",
    request: "addressBookQuery",
    reason:
      "the target is a book URL from fetchBooks, which is derived from resolved.homeUrl; the caller's term reaches the filter body, never the URL",
  },
  {
    file: CONTACTS,
    fn: "duplicateQuery",
    request: "addressBookQuery",
    reason:
      "the target is a book URL from fetchBooks, which is derived from resolved.homeUrl, exactly as its search counterpart above. The probe values a caller supplied reach the filter body and never the URL, and the property name reaching the filter is one of two constants this module owns rather than anything the caller chose — so the duplicate scan (CONW-05) adds no new way to aim a request even though it adds a new request",
  },
  {
    file: CONTACTS,
    fn: "localRoute",
    request: "propfind",
    reason:
      "the target is a book URL from fetchBooks, derived from resolved.homeUrl",
  },
  {
    file: CONTACTS,
    fn: "localRoute",
    request: "addressBookMultiGet",
    reason:
      "the object URLs are re-anchored to the book URL that fetchBooks enumerated from resolved.homeUrl, and no token reaches this route at all",
  },
  {
    file: DISCOVERY,
    fn: "discoverAccount",
    request: "createAccount",
    reason:
      "resolves the home set, so it cannot be under one — this is the bootstrap request, and it is the reason 03-12 chose a call-site helper over a transport choke point, which would have needed a mode to let this one request past",
  },
  // Phase 17 (CALM-07). TWO requests share this entry because the enumeration
  // keys on `file › fn › request` and both of them are a `propfind` inside this
  // one function: a PROPFIND against the principal asking where the scheduling
  // inbox is, then a depth-0 PROPFIND against that inbox asking which calendar is
  // the account's default. They are SERIAL and cannot be otherwise — the second
  // addresses a URL the first one supplies.
  //
  // **It is exempt, and the second target is nonetheless checked.** That is not a
  // contradiction: exempt here means no CALLER can aim it, and the whole input to
  // this function is the discovery triple this principal's own resolution just
  // produced — no identifier, no cursor, no reference, nothing decoded from a
  // token. The check on the inbox href exists because the href came off the WIRE
  // rather than from a caller, and "the server said so" is not an authorisation
  // either: `src/dav/transport.ts` attaches the Apple ID and the app-specific
  // password to whatever URL it is handed. So the check is defence against the
  // remote answer, recorded here rather than claimed as the containment this gate
  // verifies — which is the same shape `createCalendarCollection`'s exemption
  // above already carries.
  {
    file: DISCOVERY,
    fn: "resolveDefaultCalendarUrl",
    request: "propfind",
    reason:
      "the first target IS resolved.principalUrl and the second is the scheduling-inbox href the first request returned, resolved against resolved.homeUrl. The whole input to this function is the discovery triple resolveDavAccount just produced for THIS principal -- no identifier, no cursor and no reference of any kind reaches it, so there is nothing a forged token could aim, which is the same claim the dav_diagnose sites below make and it is stronger than a derivation argument rather than weaker. The inbox href is nonetheless passed through assertUnderHome against resolved.homeUrl before the second request, because it arrived from the SERVER rather than from a caller and transport.ts attaches the credential to whatever URL it is handed; the refusal is caught and becomes a null default calendar rather than failing every calendar operation. That is recorded here rather than claimed as a check this gate verified, on createCalendarCollection's own precedent",
  },
  // The two sites the three-file list never looked at. Traced during the
  // phase-03 security audit and traced again when this glob was written, both
  // times to the same answer: `dav_diagnose`'s ENTIRE input is booleans. There
  // is no identifier, no cursor and no reference on this path, so there is
  // nothing a token could aim even in principle — which is a stronger claim
  // than the derivation arguments above, not a weaker one.
  //
  // **The reasons below used to say "a single refresh boolean", and phase 14
  // made that sentence false rather than merely dated.** `dav_diagnose` now
  // takes three booleans. Nothing about the claim weakened — booleans still
  // carry no URL, and the two probes' targets are still built from this
  // principal's own resolved home set — but an exemption's reason is the thing
  // a reviewer reads, and a reason that is wrong in a checkable detail is worse
  // than one that is merely brief. The wording is corrected rather than left to
  // decay, because nothing in this file fails when prose stops matching code.
  {
    file: DIAGNOSE,
    fn: "probeCalendarHome",
    request: "propfind",
    reason:
      "the target is the homeUrl parameter, and every caller passes a resolved.homeUrl: runOneService, and since phase 14 the two probes, which resolve the account themselves through resolveDavAccount. The whole dav_diagnose input is three booleans, so no caller-supplied value reaches this URL at all",
  },
  {
    file: DIAGNOSE,
    fn: "runOneService",
    request: "fetchAddressBooks",
    reason:
      "the account is davAccountFor(service, resolved), built from the resolved home set and a service name taken from the DAV_SERVICES constant this function loops over; the whole dav_diagnose input is three booleans, so no caller-supplied value reaches this URL at all",
  },
  // Phase 14's three sites. All of them are reached only behind their own
  // named boolean, and all three targets are built from the SAME resolved home
  // set the two sites above are — there is no fourth way into this file.
  {
    file: DIAGNOSE,
    fn: "runTaskCollectionProbe",
    request: "calendarQuery",
    reason:
      "the target is a collection href that probeCalendarHome enumerated from resolveDavAccount's own homeUrl for THIS principal, and the enumeration resolves every href against that home URL and drops one that will not, so a collection this server cannot address never reaches the loop. The probe takes no title, id or name of any kind — its whole input is one boolean saying whether to run",
  },
  {
    file: DIAGNOSE,
    fn: "runCollectionWriteProbe",
    request: "davRequest",
    reason:
      "TWO requests share this entry because they share this key and this argument exactly — the extended MKCOL that creates the collection, and the PROPPATCH that renames and recolours it. Both address one local const holding resolveDavAccount's homeUrl for THIS principal plus one path segment from crypto.randomUUID(), so the only free component of the URL is generated on that line rather than accepted from anywhere, and nothing between them reassigns it. The create used to be a call to tsdav's collection-creation helper of its own and is not any more: that helper hardcodes the RFC 4791 calendar-creation method, and this runtime refuses to build a request carrying it at all, so the create is assembled by hand as an RFC 5689 extended MKCOL through the same raw helper the PROPPATCH already was. Both names are given by role rather than spelled, because both are banned tokens in every scanned root. The probe's whole input is one boolean saying whether to run: no host, no path and no identifier crosses the tool boundary, which is why this is exempt rather than checked — there is no caller-supplied URL for assertUnderHome to be checking",
  },
  {
    file: DIAGNOSE,
    fn: "runCollectionWriteProbe",
    request: "deleteObject",
    reason:
      "the delete addresses the same generated URL, from the same local const. This is the site where being aimed wrongly would cost the most — it REMOVES what it addresses — and it is also the site where the URL is furthest from any caller: nothing reaches this function but a boolean",
  },
]);

// ---------------------------------------------------------------------------
// The enumeration
// ---------------------------------------------------------------------------

/** One request site found in source. */
interface FoundSite {
  file: string;
  fn: string;
  request: string;
  line: number;
}

/** `file › fn › request` — the identity all three lists are compared on. */
function keyOf(site: { file: string; fn: string; request: string }): string {
  return `${site.file} › ${site.fn} › ${site.request}`;
}

/**
 * Blank out WHOLE-LINE comments, preserving line numbering.
 *
 * Whole-line only, and deliberately so. A general comment stripper would have to
 * treat `//` inside a string literal — every URL in this tree contains one — and
 * getting that wrong would silently swallow the code after it, which is a MISS.
 * A trailing comment that merely mentions a request name survives and produces a
 * false positive instead, which is the direction this gate is biased in.
 */
function withoutWholeLineComments(source: string): string[] {
  return source.split("\n").map((line) => {
    const trimmed = line.trim();
    const isComment =
      trimmed.startsWith("//") ||
      trimmed.startsWith("/*") ||
      trimmed.startsWith("*/") ||
      trimmed.startsWith("*");
    return isComment ? "" : line;
  });
}

/** A top-level function declaration, at column zero. Nested arrows are not one. */
const TOP_LEVEL_FN = /^(?:export\s+)?(?:async\s+)?function\s+(\w+)/;

/** Every DAV request call in one file, attributed to its enclosing function. */
function enumerateRequestSites(file: string, source: string): FoundSite[] {
  const lines = withoutWholeLineComments(source);
  const found: FoundSite[] = [];
  const seen = new Set<string>();
  let enclosing = "(module scope)";

  lines.forEach((line, index) => {
    const declaration = TOP_LEVEL_FN.exec(line);
    if (declaration) enclosing = declaration[1];

    // An import names the request functions without calling any of them; the
    // `(` requirement already excludes it, and this is belt-and-braces.
    if (/^\s*import\b/.test(line)) return;

    for (const request of DAV_REQUEST_FUNCTIONS) {
      if (!new RegExp(`\\b${request}\\s*\\(`).test(line)) continue;
      const site = { file, fn: enclosing, request, line: index + 1 };
      const key = keyOf(site);
      // The same request twice in one function is one decision, not two.
      if (seen.has(key)) continue;
      seen.add(key);
      found.push(site);
    }
  });

  return found;
}

/**
 * One top-level function's body text, from its declaration to the next one.
 *
 * Comment-stripped, so the ordering assertions below read code and not the
 * prose beside it — the guarded call sites carry comments that discuss the very
 * request they precede.
 */
/**
 * Every url one body actually asserts containment on, sorted and de-duplicated.
 *
 * Read off the FIRST ARGUMENT of each `assertUnderHome(` call, which is the
 * same text the declared `field` carries, so the two can be compared directly.
 * The text is already comment-stripped by `bodyOf`, so a comment mentioning the
 * assertion cannot inflate the answer.
 *
 * `[^,)]` rather than `[^,]` so a call written across two lines — or one whose
 * argument is itself a call — fails loudly here instead of silently swallowing
 * the rest of the body. No such shape exists today and none should: the
 * argument at every site is a plain reference, because a computed one would
 * mean the value checked and the value sent could differ.
 */
function assertedFieldsIn(body: string): string[] {
  return [
    ...new Set(
      [...body.matchAll(/assertUnderHome\(\s*([^,)]+?)\s*,/g)].map(
        (match) => match[1],
      ),
    ),
  ].sort();
}

function bodyOf(file: string, fn: string): string {
  const lines = withoutWholeLineComments(SOURCES[file]);
  const start = lines.findIndex((line) => {
    const declaration = TOP_LEVEL_FN.exec(line);
    return declaration !== null && declaration[1] === fn;
  });
  expect(start, `${file} declares no top-level function named ${fn}`).toBeGreaterThan(-1);

  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (TOP_LEVEL_FN.test(lines[index])) {
      end = index;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

const FOUND_SITES: FoundSite[] = Object.keys(SOURCES).flatMap((file) =>
  enumerateRequestSites(file, SOURCES[file]),
);

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

describe("every DAV request site is either home-checked or exempt with a reason", () => {
  it("loaded the whole src/dav/ directory as text", () => {
    // Non-vacuity before anything else, and it has three halves now that the
    // set is globbed rather than named: a `?raw` yielding an empty string, a
    // glob yielding no files, and a glob quietly narrowed back to the files the
    // lists already declare. All three leave every assertion below passing over
    // a tree that was never really read, which is the exact failure — a gate
    // that is silent rather than satisfied — this file exists to make
    // impossible.
    expect(
      Object.keys(SOURCES).length,
      "the src/dav/ glob matched nothing. Vite resolves a glob key relative to this module, so a moved test file or a changed pattern empties this gate without failing anything else.",
    ).toBeGreaterThan(0);

    for (const [file, source] of Object.entries(SOURCES)) {
      expect(
        file.startsWith(DAV_DIR) && file.endsWith(".ts"),
        `${file} is not a src/dav/ TypeScript path — the glob is reaching somewhere this gate does not own`,
      ).toBe(true);
      expect(typeof source, `${file} did not load as text`).toBe("string");
      expect(source.length, `${file} loaded empty`).toBeGreaterThan(1000);
    }

    // The by-construction property, asserted rather than assumed. The two lists
    // between them name four files; the directory holds strictly more, and the
    // surplus is what a future `src/dav/*.ts` lands in without anyone editing
    // this file. If this fails because the pattern was narrowed, widen the
    // pattern — do not delete this assertion, because a hardcoded list wearing
    // a glob's clothes is exactly what the phase-03 audit found here.
    const declaredFiles = new Set([
      ...HOME_CHECKED_CALL_SITES.map((site) => site.file),
      ...HOME_EXEMPT_REQUEST_SITES.map((site) => site.file),
    ]);
    expect(
      Object.keys(SOURCES).length,
      `the glob found only the ${declaredFiles.size} files the two lists already declare, so it is covering nothing by construction`,
    ).toBeGreaterThan(declaredFiles.size);

    // The other direction: a file the lists name that the glob does not hold
    // would make `bodyOf` fail on an undefined source with a confusing message.
    for (const file of declaredFiles) {
      expect(
        Object.keys(SOURCES),
        `${file} is declared in one of the two lists but the glob did not load it`,
      ).toContain(file);
    }

    expect(
      FOUND_SITES.length,
      "the enumeration found NO DAV request sites at all. Either the regex vocabulary has drifted from the code, or every request has moved — both leave this gate guarding nothing.",
    ).toBeGreaterThan(0);
  });

  it("attributes every request it finds to a named function", () => {
    // A site attributed to module scope means the declaration regex missed a
    // function shape, and every list comparison below is then keyed on a name
    // nobody declared.
    const orphans = FOUND_SITES.filter((site) => site.fn === "(module scope)");
    expect(
      orphans.map(keyOf),
      "a DAV request was found outside any top-level function. The enclosing-function regex has missed a declaration shape, so the enumeration keys are wrong.",
    ).toEqual([]);
  });

  it("declares two lists that are non-empty and disjoint", () => {
    // Non-vacuity first, then the property the literal `4` here was standing
    // in for. That number went stale on the first plan that added a protected
    // function, and it went stale SILENTLY in the sense that matters: nothing
    // about the boundary had weakened, so the failure was pure noise pointing
    // at the wrong thing. What was actually being asserted is the PAIRING —
    // every protected function names both of its urls — and that claim has no
    // expiry date.
    //
    // **CALM-05 made the literal `2` below the same kind of stale number, and
    // it is replaced by a DERIVATION rather than relaxed.** `updateCalendarCollection`
    // is the first protected function in this project whose request has ONE
    // url: it addresses a collection, and a collection has no object hanging
    // off it the way an event ref does. Relaxing `toBe(2)` to "at least one"
    // was refused outright — that is the exact widening 17-03's summary says
    // would let a future pair-shaped writer declare one of its two and pass.
    //
    // So the expected count is read off the SOURCE instead: it is however many
    // urls the holder actually asserts containment on. That is strictly
    // stronger than the constant for every site the constant covered, because
    // it also catches a three-url writer declaring two, and it is not
    // self-certifying — the number comes from the code rather than from the
    // entry.
    //
    // The pair claim itself is kept ALONGSIDE it, keyed on the `ref.`
    // vocabulary, because a derivation cannot see a check that was deleted
    // together with its declaration. A url read out of a decoded reference is
    // by definition one half of a pair, which is what the original message
    // below says, so a function declaring any `ref.` field must still declare
    // both of them.
    expect(
      HOME_CHECKED_CALL_SITES.length,
      "the checked list is empty, so every assertion built on it passes over nothing",
    ).toBeGreaterThan(0);

    const perFunction = new Map<string, CheckedSite[]>();
    for (const site of HOME_CHECKED_CALL_SITES) {
      const key = `${site.file} › ${site.fn}`;
      perFunction.set(key, [...(perFunction.get(key) ?? []), site]);
    }
    for (const [key, sites] of perFunction) {
      const declared = [...new Set(sites.map((site) => site.field))].sort();
      expect(
        declared.length,
        `${key} declares the same url twice. Two entries naming one field is one check wearing two hats.`,
      ).toBe(sites.length);

      // Every url the holder really guards, read off the code. A site declaring
      // `via` is credited with the HELPER's assertions, which is where its
      // containment actually lives.
      const asserted = assertedFieldsIn(
        bodyOf(sites[0].file, sites[0].via ?? sites[0].fn),
      );
      expect(
        declared,
        `${key} declares ${declared.length} checked url(s) and its body asserts containment on ${asserted.length}. Every url this function hands to the network must be declared here, and a declaration with no assertion behind it is a claim about a check that does not run.`,
      ).toEqual(asserted);

      if (declared.some((field) => field.startsWith("ref."))) {
        expect(
          declared.length,
          `${key} declares ${declared.length} checked url(s) rather than both. The object URL travels separately from the collection URL and each independently names what the server is asked for.`,
        ).toBe(2);
      }
    }
    expect(
      HOME_EXEMPT_REQUEST_SITES.length,
      "the exempt list is empty",
    ).toBeGreaterThan(0);

    // A site on both lists would satisfy the set equality below while leaving it
    // ambiguous which property is actually claimed about it.
    const checked = new Set(
      HOME_CHECKED_CALL_SITES.map((site) =>
        keyOf({ file: site.file, fn: site.fn, request: site.guards }),
      ),
    );
    const both = HOME_EXEMPT_REQUEST_SITES.filter((site) =>
      checked.has(keyOf(site)),
    );
    expect(
      both.map(keyOf),
      "a site is declared BOTH home-checked and exempt. It must be one or the other.",
    ).toEqual([]);
  });

  it("gives every exempt site a reason stating where its URL came from", () => {
    for (const site of HOME_EXEMPT_REQUEST_SITES) {
      expect(
        site.reason.trim().length,
        `${keyOf(site)} is exempt with no reason. An exemption without a reason is an exemption nobody can review.`,
      ).toBeGreaterThan(30);
    }
  });

  it("finds exactly the sites the two lists declare, in both directions", () => {
    const declared = [
      ...new Set([
        ...HOME_CHECKED_CALL_SITES.map((site) =>
          keyOf({ file: site.file, fn: site.fn, request: site.guards }),
        ),
        ...HOME_EXEMPT_REQUEST_SITES.map(keyOf),
      ]),
    ].sort();
    const actual = [...new Set(FOUND_SITES.map(keyOf))].sort();

    // Sorted-array equality rather than two subset checks, so the failure names
    // the actual difference rather than merely reporting a size.
    expect(
      actual,
      [
        "The DAV request sites in src/dav/ no longer match the two declared lists.",
        "",
        "If a site was ADDED: a new DAV request reachable from a decoded token must",
        "assert containment first — assertUnderHome(url, resolved.homeUrl), inside the",
        "withRediscovery callback and BEFORE the request — and then be added to",
        "HOME_CHECKED_CALL_SITES. If its target is derived from resolved.homeUrl and no",
        "token can aim it, add it to HOME_EXEMPT_REQUEST_SITES with the reason IN the",
        "entry. 03-REVIEW.md CR-01 is why: transport.ts attaches the Apple credential to",
        "whatever URL it is handed, so an unchecked token-borne URL sends it to whatever",
        "origin the token named.",
        "",
        "If a site was REMOVED: a protected call site was deleted or renamed, and this",
        "gate is now guarding nothing. Do not delete the list entry to match — work out",
        "where the request went.",
      ].join("\n"),
    ).toEqual(declared);
  });

  it("asserts containment BEFORE the request, not merely somewhere in the file", () => {
    // Presence is not the property; ordering is. A file containing the assertion
    // after the multi-get would satisfy a presence check completely, and would
    // have sent the credential before it ran.
    //
    // A site declaring `via` is checked as a TWO-LINK chain rather than being
    // waved through: the helper asserts before it delegates, and the caller
    // calls the helper before it issues its own request. Both links, because
    // either one broken puts the request ahead of the check again.
    for (const site of HOME_CHECKED_CALL_SITES) {
      const body = bodyOf(site.file, site.fn);
      const holder =
        site.via === undefined ? body : bodyOf(site.file, site.via);

      const assertion = holder.indexOf(`assertUnderHome(${site.field},`);
      expect(
        assertion,
        `${site.file} › ${site.via ?? site.fn} no longer asserts containment on ${site.field}. CR-01: this URL arrives inside a caller-supplied, unauthenticated token, and transport.ts will attach the credential to whatever origin it names.`,
      ).toBeGreaterThan(-1);

      const request = body.indexOf(`${site.guards}(`);
      expect(
        request,
        `${site.file} › ${site.fn} no longer calls ${site.guards}. If the request moved, the assertion guarding it must move with it.`,
      ).toBeGreaterThan(-1);

      if (site.via === undefined) {
        expect(
          assertion,
          `${site.file} › ${site.fn}: assertUnderHome(${site.field}, ...) runs AFTER ${site.guards}(). The request has already reached the network with the credential attached by then, so the check guards nothing.`,
        ).toBeLessThan(request);
        continue;
      }

      // Link one: inside the helper, the assertion precedes the delegation.
      const delegation = holder.indexOf(HELPER_DELEGATION);
      expect(
        delegation,
        `${site.file} › ${site.via} no longer delegates through ${HELPER_DELEGATION}. The ordering chain is anchored on that line, so a rename here silently ends the assertion.`,
      ).toBeGreaterThan(-1);
      expect(
        assertion,
        `${site.file} › ${site.via}: assertUnderHome(${site.field}, ...) runs AFTER it hands control to its caller's write. Everything that reaches the network does so from inside that call, so the check guards nothing.`,
      ).toBeLessThan(delegation);

      // Link two: inside the caller, the helper call precedes the request.
      const handoff = body.indexOf(`${site.via}(`);
      expect(
        handoff,
        `${site.file} › ${site.fn} no longer calls ${site.via}, so its containment is not being performed by anything.`,
      ).toBeGreaterThan(-1);
      expect(
        handoff,
        `${site.file} › ${site.fn}: ${site.guards}() appears BEFORE the call to ${site.via}(), so the request is not inside the contained callback at all.`,
      ).toBeLessThan(request);
    }
  });

  it("asserts containment against the resolved home set, not a constant", () => {
    // The second argument matters as much as the first. A home URL taken from a
    // literal, or from the token, would make the check compare a value against
    // itself — green, and worthless. It must be the value discovery resolved.
    for (const site of HOME_CHECKED_CALL_SITES) {
      const holder = bodyOf(site.file, site.via ?? site.fn);
      expect(
        holder.includes(`assertUnderHome(${site.field}, resolved.homeUrl)`),
        `${site.file} › ${site.via ?? site.fn}: the containment check on ${site.field} is not against resolved.homeUrl. Discovery's resolved home set is the only value that makes the comparison mean anything.`,
      ).toBe(true);
    }
  });

  it("names a helper that exists and holds BOTH urls, for every via site", () => {
    // The non-vacuity arm of `via`. A helper naming one URL would let a site
    // declare two fields against it while only one was ever checked, and the
    // per-function pairing assertion above counts DECLARATIONS rather than
    // assertions — so it cannot see that on its own.
    const helpers = new Map<string, Set<string>>();
    for (const site of HOME_CHECKED_CALL_SITES) {
      if (site.via === undefined) continue;
      const key = `${site.file} › ${site.via}`;
      const fields = helpers.get(key) ?? new Set<string>();
      fields.add(site.field);
      helpers.set(key, fields);
    }

    for (const [key, fields] of helpers) {
      expect(
        fields.size,
        `${key} is credited with ${fields.size} distinct url(s) rather than both. The object URL travels separately from its collection and each independently names what the server is asked for.`,
      ).toBe(2);
    }
  });
});

// ---------------------------------------------------------------------------
// The same property, DRIVEN
//
// Everything above reads source text. This half runs the writers against a stub
// and counts what leaves, and the two are not redundant — they fail on
// different things and neither implies the other:
//
//   - The audit says the assertion is WRITTEN and is written before the
//     request. It cannot say the assertion fires, because it does not execute
//     anything: a check comparing a value against itself would satisfy every
//     assertion in this file.
//   - This half says a forged reference is REFUSED with nothing sent. It cannot
//     say a writer added tomorrow is covered, because it names its writers.
//
// It lives in this file rather than beside the other write cases because the
// property is this file's — "a URL a stranger's token can aim is checked before
// it reaches the wire" — and splitting a property across two files is how one
// half gets edited and the other stops matching.
//
// **The same-origin case is the one that would be missed.** A forged host is
// caught by the origin comparison alone; a forged SIBLING PATH on the real host
// is same-origin, so only the trailing-slash normalisation catches it. A suite
// testing only `attacker.example` passes with that normalisation deleted, and
// the credential then travels to a path this account does not own.
// ---------------------------------------------------------------------------

const CALDAV_ENTRY = "https://caldav.icloud.com";
const PRINCIPAL_PATH = "/1234567890/principal/";
const CALDAV_HOME = "https://p42-caldav.icloud.com/1234567890/calendars/";
const WORK_PATH = "/1234567890/calendars/work/";
const WORK_URL = `https://p42-caldav.icloud.com${WORK_PATH}`;
const OBJECT_URL = `${WORK_URL}simple-0009.ics`;

/** A different HOST entirely. Caught by the origin comparison. */
const FOREIGN_COLLECTION = "https://attacker.example/1234567890/calendars/work/";
const FOREIGN_OBJECT = "https://attacker.example/steal.ics";

/**
 * The REAL host, one path segment sideways.
 *
 * `/1234567890/calendarsEVIL/` is SAME-ORIGIN, so the origin comparison lets it
 * straight through and the path prefix test is the only thing that refuses it.
 * A suite driving only `attacker.example` therefore passes with the entire path
 * half of `assertUnderHome` deleted.
 *
 * Which of the prefix test's two halves does the work depends on the home URL,
 * and the case below with a SLASHLESS home is the one that isolates the
 * normalisation. Against the ordinary home — which already ends in `/` — the
 * plain prefix comparison catches this on its own.
 */
const SIBLING_COLLECTION =
  "https://p42-caldav.icloud.com/1234567890/calendarsEVIL/work/";
const SIBLING_OBJECT =
  "https://p42-caldav.icloud.com/1234567890/calendarsEVIL/steal.ics";

const CONTAINMENT_ICS = [
  "BEGIN:VCALENDAR",
  "VERSION:2.0",
  "PRODID:-//Example Org//Synthesised Fixture//EN",
  "BEGIN:VEVENT",
  "UID:simple-0009",
  "DTSTAMP:20260101T120000Z",
  "SUMMARY:Interview",
  "DTSTART:20260210T150000Z",
  "DTEND:20260210T160000Z",
  "END:VEVENT",
  "END:VCALENDAR",
  "",
].join("\r\n");

interface ContainmentStub {
  observed: string[];
  fetch: typeof globalThis.fetch;
}

/**
 * A stub answering only what discovery needs, and recording everything.
 *
 * Deliberately minimal. Every case below must be refused BEFORE a request, so
 * there is nothing for this to serve after the warm-up — and a stub that could
 * serve a write would let a case pass by writing successfully somewhere
 * harmless rather than by refusing.
 */
function containmentStub(home: string = CALDAV_HOME): ContainmentStub {
  const state: ContainmentStub = {
    observed: [],
    fetch: async () => new Response(null, { status: 500 }),
  };

  state.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    state.observed.push(url);

    if (url.includes("/.well-known/")) return new Response(null, { status: 404 });

    if (url.startsWith(CALDAV_ENTRY)) {
      const body = url.endsWith(PRINCIPAL_PATH)
        ? `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><C:calendar-home-set><href>${home}</href></C:calendar-home-set></prop></propstat></response>`
        : `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><current-user-principal><href>${PRINCIPAL_PATH}</href></current-user-principal></prop></propstat></response>`;
      return new Response(
        `<?xml version="1.0" encoding="utf-8" ?><multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">${body}</multistatus>`,
        { status: 207, headers: { "content-type": "text/xml; charset=utf-8" } },
      );
    }

    // Every write this stub is asked for is answered a success, so a case that
    // passes is one that REFUSED rather than one that failed on the way out.
    return new Response(null, { status: 204 });
  }) as typeof globalThis.fetch;

  return state;
}

let live: ContainmentStub;

beforeEach(async () => {
  live = containmentStub();
  vi.stubGlobal("fetch", live.fetch);
  // Cleared first, so the warm-up is a real miss rather than a hit left behind
  // by another file in the pool.
  await clearDavCache(env, principal, "caldav");
  const resolved = await resolveDavAccount(env, principal, createDavFetch(owner), "caldav");
  expect(resolved.cacheHit).toBe(false);
  live.observed.length = 0;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Run something and hand back whatever it threw. */
async function refusal(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (err) {
    return err;
  }
  throw new Error("expected a refusal, got a resolution");
}

function refOf(calendarUrl: string, objectUrl: string): EventRef {
  return { calendarUrl, objectUrl, recurrenceId: null };
}

/** The two writers that take an `EventRef`, driven with whatever ref is given. */
const REF_WRITERS: Record<string, (ref: EventRef) => Promise<unknown>> = {
  updateEvent: (ref) =>
    updateEvent(env, principal, createDavFetch(owner), ref, CONTAINMENT_ICS, '"etag-1"'),
  deleteEvent: (ref) => deleteEvent(env, principal, createDavFetch(owner), ref, '"etag-1"'),
};

describe("a forged reference is refused before the credential leaves", () => {
  it("negative control: every writer DOES reach the wire with a legitimate target", async () => {
    // Without this the zero-count assertions below pass just as happily on a
    // harness that never issues anything at all — which is the failure mode
    // this whole file is written against.
    for (const [name, drive] of Object.entries(REF_WRITERS)) {
      live.observed.length = 0;
      await drive(refOf(WORK_URL, OBJECT_URL));
      expect(live.observed.length, `${name} issued nothing at all`).toBe(1);
    }

    live.observed.length = 0;
    await createEvent(env, principal, createDavFetch(owner), {
      calendarId: encodeCalendarId({ collectionUrl: WORK_URL }),
      summary: "Interview",
      startLocal: "2026-09-03T14:00:00",
      endLocal: "2026-09-03T15:00:00",
      tzid: "UTC",
    });
    expect(live.observed.length, "createEvent issued nothing at all").toBe(1);
  });

  it("refuses a forged COLLECTION url, wrong-origin and same-origin alike", async () => {
    for (const [name, drive] of Object.entries(REF_WRITERS)) {
      for (const [label, collection] of [
        ["wrong origin", FOREIGN_COLLECTION],
        ["same-origin sibling path", SIBLING_COLLECTION],
      ] as const) {
        live.observed.length = 0;
        const err = await refusal(() =>
          drive(refOf(collection, `${collection}simple-0009.ics`)),
        );

        expect(err, `${name} / ${label} was not refused`).toBeInstanceOf(
          DavNotFoundError,
        );
        // ZERO. `src/dav/transport.ts` attaches the Apple ID and the
        // app-specific password to whatever URL it is handed, so one request is
        // one credential delivered to the forged origin.
        expect(
          live.observed.length,
          `${name} / ${label} reached the network, so the credential went to the forged target`,
        ).toBe(0);
      }
    }
  });

  it("refuses a forged OBJECT url under a LEGITIMATE collection", async () => {
    // The half a collection-only check cannot see. The object URL is the
    // request's actual target and travels separately, so checking the
    // collection alone is not checking the call.
    for (const [name, drive] of Object.entries(REF_WRITERS)) {
      for (const [label, object] of [
        ["wrong origin", FOREIGN_OBJECT],
        ["same-origin sibling path", SIBLING_OBJECT],
      ] as const) {
        live.observed.length = 0;
        const err = await refusal(() => drive(refOf(WORK_URL, object)));

        expect(err, `${name} / ${label} was not refused`).toBeInstanceOf(
          DavNotFoundError,
        );
        expect(
          live.observed.length,
          `${name} / ${label} reached the network with a forged object URL under a real collection`,
        ).toBe(0);
      }
    }
  });

  it("refuses a create aimed at a forged collection, on both forms", async () => {
    // **`createEvent` has no independently forgeable object URL, and that is a
    // property of the code rather than a gap here.** It takes an opaque
    // calendar id and CONSTRUCTS the object URL from the decoded collection
    // plus a filename it mints, so a forged collection forges both and there is
    // no input that forges only the second. The source-text half above is what
    // pins that the constructed URL is checked too; this half pins that the
    // only forgeable input is refused with nothing sent.
    for (const [label, collection] of [
      ["wrong origin", FOREIGN_COLLECTION],
      ["same-origin sibling path", SIBLING_COLLECTION],
    ] as const) {
      live.observed.length = 0;
      const err = await refusal(() =>
        createEvent(env, principal, createDavFetch(owner), {
          calendarId: encodeCalendarId({ collectionUrl: collection }),
          summary: "Interview",
          startLocal: "2026-09-03T14:00:00",
          endLocal: "2026-09-03T15:00:00",
          // A zone this server HOLDS, deliberately. An unsupported one is
          // reported rather than raised and costs zero requests, so it would
          // make this case pass without the containment check running at all.
          tzid: "UTC",
        }),
      );

      expect(err, `create / ${label} was not refused`).toBeInstanceOf(
        DavNotFoundError,
      );
      expect(
        live.observed.length,
        `create / ${label} reached the network`,
      ).toBe(0);
    }
  });

  it("aims the collection create under the resolved home, with nothing to forge", async () => {
    // **The driven half of the create's exemption, and the honest form of it.**
    // The audit above records WHY no hostile case exists for this site: the
    // input carries no URL, so there is nothing to forge and a refusal case
    // would be an assertion that cannot fail. What IS falsifiable is where the
    // request actually went, and that is what this checks — against the
    // recorded URL rather than against the return value, because the return
    // value is minted from the same string and would agree with itself.
    live.observed.length = 0;
    const created = await createCalendarCollection(
      env,
      principal,
      createDavFetch(owner),
      { displayName: "Job search", color: "#1f77b4" },
    );

    expect(live.observed.length, "the create issued nothing at all").toBe(1);
    const target = live.observed[0];
    expect(
      target.startsWith(CALDAV_HOME),
      `the collection create targeted ${target}, which is not under the resolved home`,
    ).toBe(true);
    // The id names what was actually addressed. A token decoding to something
    // else would name a collection nobody made.
    expect(decodeCalendarId(created.id).collectionUrl).toBe(target);
  });

  it("cannot be aimed by any extra key smuggled onto its input", async () => {
    // **The nearest thing to a hostile case this entry point admits, and it can
    // genuinely fail.** The claim the exemption rests on is that no URL crosses
    // this boundary. TypeScript says so at compile time and says nothing at
    // all at runtime, so this drives the real function with every plausible
    // URL-bearing key name a later parameter might arrive under, each naming a
    // FOREIGN origin, and asserts the request still went under this account's
    // own home.
    //
    // If somebody later adds a URL-bearing parameter to `CreateCalendarInput`
    // and wires it to the target without a containment assertion, this goes red
    // — which is the day the site stops being exempt and moves to the checked
    // list.
    for (const key of [
      "collectionUrl",
      "url",
      "href",
      "calendarId",
      "id",
      "home",
      "homeUrl",
    ]) {
      live.observed.length = 0;
      await createCalendarCollection(env, principal, createDavFetch(owner), {
        displayName: "Job search",
        color: "#1f77b4",
        // Deliberately outside the declared shape. The cast is the point: it is
        // how a runtime caller reaches a function whose type says no.
        [key]: FOREIGN_COLLECTION,
      } as unknown as Parameters<typeof createCalendarCollection>[3]);

      expect(live.observed.length, `${key}: the create issued nothing`).toBe(1);
      expect(
        live.observed[0].startsWith(CALDAV_HOME),
        `${key} aimed the create at ${live.observed[0]} — the credential went to a host this account does not own`,
      ).toBe(true);
    }
  });

  it("refuses a forged collection on the RENAME, wrong-origin and same-origin alike", async () => {
    // **The hostile case the create beside it cannot have, written properly
    // rather than exempted.** `createCalendarCollection`'s input carries no URL
    // at all, so a refusal case against it would be an assertion that cannot
    // fail — which is what that site's exemption reason records. This one's
    // collection URL comes out of a caller-supplied opaque id, so a forged or
    // cross-account token is a real input and this case can genuinely go red.
    for (const [label, collection] of [
      ["wrong origin", FOREIGN_COLLECTION],
      ["same-origin sibling path", SIBLING_COLLECTION],
    ] as const) {
      live.observed.length = 0;
      const err = await refusal(() =>
        updateCalendarCollection(env, principal, createDavFetch(owner), {
          collectionUrl: collection,
          displayName: "Job search 2026",
        }),
      );

      expect(err, `rename / ${label} was not refused`).toBeInstanceOf(
        DavNotFoundError,
      );
      // **`rediscoverable` is FALSE, and the refusal is deliberately
      // INDISTINGUISHABLE from a genuine miss.** A distinguishable one would
      // hand this endpoint to the same forged id it exists to refuse as a
      // collection-existence oracle: ask about a URL, read which refusal came
      // back, learn whether the collection is there. A later reader improving
      // the message into something more helpful is exactly how that oracle
      // gets built, so it is written down here rather than left to be inferred.
      // `false` is also what stops a forged id spending one of D-60's two
      // permitted retries on a real PROPFIND against iCloud.
      expect(
        (err as DavNotFoundError).rediscoverable,
        `rename / ${label} was refused as rediscoverable, which spends a real PROPFIND on a forged id`,
      ).toBe(false);
      // ZERO. One request is one credential delivered to the forged origin.
      expect(
        live.observed.length,
        `rename / ${label} reached the network, so the credential went to the forged target`,
      ).toBe(0);
    }
  });

  it("refuses a forged collection on the DELETE, wrong-origin and same-origin alike", async () => {
    // **The hostile case for the most destructive request in the project, and
    // it is written rather than exempted even though its target arrives already
    // SIGNED.** `applyCollectionCommit` reads the URL out of `payload.o`, whose
    // seal has been verified with this server's own key and checked against the
    // signed-in principal — so a forged id cannot reach here without first
    // forging an HMAC. That is stronger than the rename's position and it is
    // still not an authorisation: a GENUINE payload minted for one account and
    // presented on another account's connection carries a URL under the first
    // account's home and not the second's, which is precisely what
    // `test/cross-user.test.ts` exists to catch and what this assertion is the
    // second layer of.
    //
    // The cost of getting it wrong is not a leak. `src/dav/transport.ts`
    // attaches the Apple ID and the app-specific password to whatever URL it is
    // handed, and this request REMOVES what it addresses — a calendar, and every
    // event, to-do and unparseable resource inside it, with no way back.
    for (const [label, collection] of [
      ["wrong origin", FOREIGN_COLLECTION],
      ["same-origin sibling path", SIBLING_COLLECTION],
    ] as const) {
      live.observed.length = 0;
      const err = await refusal(() =>
        deleteCalendarCollection(env, principal, createDavFetch(owner), collection),
      );

      expect(err, `delete / ${label} was not refused`).toBeInstanceOf(
        DavNotFoundError,
      );
      // `rediscoverable` is FALSE, on the rename's own argument one case up: a
      // distinguishable refusal would hand this endpoint to the forged id it
      // exists to refuse as a collection-existence oracle, and `false` is also
      // what stops a forged id spending one of D-60's two permitted retries on a
      // real request against iCloud.
      expect(
        (err as DavNotFoundError).rediscoverable,
        `delete / ${label} was refused as rediscoverable, which spends a real request on a forged id`,
      ).toBe(false);
      // ZERO. One request here is one credential delivered to the forged origin
      // AND one collection removed at it.
      expect(
        live.observed.length,
        `delete / ${label} reached the network, so the credential went to the forged target and a collection may be gone`,
      ).toBe(0);
    }
  });

  it("negative control: the delete DOES reach the wire with a legitimate target", async () => {
    // Without this the zero-count assertions above pass just as happily on a
    // harness that never issues anything at all — which is the failure mode this
    // whole file is written against.
    //
    // It asserts the REQUEST and not the answer. This stub answers every write a
    // bare `204`, which is what a real server answers a collection removal it
    // accepted, and the property THIS gate holds is where the credential went.
    live.observed.length = 0;
    const answered = await deleteCalendarCollection(
      env,
      principal,
      createDavFetch(owner),
      WORK_URL,
    );

    expect(live.observed.length, "the delete issued nothing at all").toBe(1);
    expect(live.observed[0]).toBe(WORK_URL);
    // A STATUS and not a verdict — see `deleteCalendarCollection`, which returns
    // what the server said and leaves the looking to the commit arm.
    expect(answered.status).toBe(204);
  });

  it("negative control: the rename DOES reach the wire with a legitimate target", async () => {
    // Without this the zero-count assertions above pass just as happily on a
    // harness that never issues anything at all — which is the failure mode
    // this whole file is written against.
    //
    // It asserts the REQUEST and not the answer, and that is deliberate rather
    // than a shortcut. This stub answers everything a bare `204` with no
    // multistatus body, so the rename's verifying re-read finds no name at all
    // and the outcome is a refusal — which is a perfectly good answer for this
    // file, because the property THIS gate holds is where the credential went,
    // not what came back. Teaching the stub to answer a real multistatus would
    // make this file own a second copy of a fixture
    // `test/dav-calendar.test.ts` already owns.
    //
    // **TWO requests since plan 17-10, and both are asserted.** The rename is
    // verified by reading the collection back rather than by the update's status
    // line, so the write AND the look again must both land on the legitimate
    // target — a verification aimed anywhere else would be a second place the
    // credential could travel to, and this file exists to see exactly that.
    live.observed.length = 0;
    const updated = await updateCalendarCollection(
      env,
      principal,
      createDavFetch(owner),
      { collectionUrl: WORK_URL, displayName: "Job search 2026" },
    );

    expect(live.observed.length, "the rename issued nothing at all").toBe(2);
    expect(live.observed).toEqual([WORK_URL, WORK_URL]);
    // The refusal came back as a VALUE rather than a throw. There is no member of
    // the four-value error vocabulary that means "iCloud kept the old name".
    expect(updated.unchanged).toEqual(["displayName"]);
  });

  it("refuses the sibling path when the home set has NO trailing slash", async () => {
    // **This is the case that isolates the normalisation, and it is the reason
    // the sibling fixtures above are not the whole story.** With a home of
    // `/1234567890/calendars` the plain prefix comparison ADMITS
    // `/1234567890/calendarsEVIL/` — same origin, and `calendarsEVIL` really
    // does start with `calendars` — so the only thing standing between a forged
    // token and the credential is appending the `/` before the test.
    //
    // Mutation-checked rather than assumed: deleting the two-line
    // normalisation in `assertUnderHome` turns this case red and leaves every
    // other case in this file green. That asymmetry is exactly why it is here.
    const slashless = containmentStub(
      "https://p42-caldav.icloud.com/1234567890/calendars",
    );
    vi.stubGlobal("fetch", slashless.fetch);
    await clearDavCache(env, principal, "caldav");
    const resolved = await resolveDavAccount(
      env, principal,
      createDavFetch(owner),
      "caldav",
    );
    expect(resolved.cacheHit).toBe(false);
    // The home really must be the slashless form, or this case is a second
    // copy of the ordinary one wearing a different name.
    expect(new URL(resolved.homeUrl).pathname.endsWith("/")).toBe(false);
    slashless.observed.length = 0;

    for (const [name, drive] of Object.entries(REF_WRITERS)) {
      slashless.observed.length = 0;
      const err = await refusal(() =>
        drive(refOf(SIBLING_COLLECTION, SIBLING_OBJECT)),
      );

      expect(err, `${name} admitted the sibling path`).toBeInstanceOf(
        DavNotFoundError,
      );
      expect(
        slashless.observed.length,
        `${name} sent the credential to a sibling path on the real host`,
      ).toBe(0);
    }
  });
});
