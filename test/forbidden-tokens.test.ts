// The test-time half of the three-layer ban (FND-06, D-11, D-12, D-13).
//
// Every pattern is imported from scripts/forbidden-tokens.mjs and never
// restated here, so this file and .husky/pre-commit cannot drift apart about
// what is banned. The violating strings below exist only to prove the patterns
// are not vacuous; that is exactly why this file's path is in the scanner's
// EXCLUDED set, and the tests under "self-exclusion" prove that skip is real
// rather than decorative.
//
// This file runs under Node rather than inside workerd (see vitest.config.ts):
// it reads the repository off disk, and a Workers isolate has no filesystem to
// read. Every filesystem access lives behind the scanner's own API, so nothing
// here imports node:fs and the project needs no Node type package.

import { describe, expect, it } from "vitest";
import {
  ADDRESS_HASH,
  ADDRESS_HASH_OWNER,
  ADDRESS_HASH_SCOPE,
  APPEND_COMMAND,
  APPEND_OWNER,
  APPEND_SCOPE,
  CONFIRM_LINE_COMPOSER,
  CONFIRM_LINE_OWNER,
  CONFIRM_LINE_SCOPE,
  DAV_FETCH_CALL,
  DAV_FETCH_OWNER,
  DAV_HOST_LITERAL,
  DAV_HOST_OWNER,
  DAV_WRITE_MODULES,
  EXCLUDED,
  FORBIDDEN,
  OWNERSHIP_VIOLATION_IDS,
  PASSWORD_READER_IMPORT,
  PASSWORD_READER_OWNERS,
  PASSWORD_READER_SCOPE,
  PRINCIPAL_CONSTRUCTOR,
  PRINCIPAL_CONSTRUCTOR_OWNERS,
  PRINCIPAL_CONSTRUCTOR_SCOPE,
  PROPS_READER,
  PROPS_READER_OWNER,
  PROPS_READER_SCOPE,
  SOCKET_IMPORT,
  SOCKET_OWNER,
  SUBSCRIPTION_FEED_FETCH_CALL,
  SUBSCRIPTION_FEED_FETCH_OWNER,
  checkAddressHashOwnership,
  checkAppendOwnership,
  checkCommitHook,
  checkConfirmLineOwnership,
  checkDavFetchOwnership,
  checkDavHostOwnership,
  checkDavWriteCoverage,
  checkPasswordReaderOwnership,
  checkPrincipalConstructorOwnership,
  checkPropsReaderOwnership,
  checkSocketOwnership,
  checkSubscriptionFeedFetchOwnership,
  davAlternationNames,
  exportedFunctionNames,
  formatViolation,
  matchRule,
  scan,
  scanWranglerConfig,
} from "../scripts/forbidden-tokens.mjs";

const SCANNER_PATH = "scripts/forbidden-tokens.mjs";
const THIS_TEST_PATH = "test/forbidden-tokens.test.ts";

/** The rules this phase adds that are scoped to the DAV tree. Named once so a
 *  rule added to the ban list without a scope test is a missing name rather
 *  than a silent omission.
 *
 *  `dav-concurrent-request` is deliberately NOT here. It began on this list and
 *  was widened to `src/` by 03-REVIEW.md WR-03, because its mail sibling
 *  `concurrent-session` names the orchestrator rather than the primitive and
 *  needs the whole source tree to reach it — a fan-out over `getEvent` is
 *  written in `src/mcp/tools/`, where no tsdav name is even in scope. Its own
 *  block below asserts both halves of that reach. */
const DAV_RULE_IDS = ["dav-eager-load", "ical-jsdate"];

/** The realistic fan-out shape, with one entry point substituted in.
 *
 *  The transport parameter is deliberately NOT spelled `davFetch`. That name is
 *  itself on the alternation, so a template carrying it matches on every
 *  iteration no matter what `entryPoint` is — the per-name loops below would
 *  pass unchanged with the whole alternation deleted down to that single name,
 *  which is a gate that cannot fail. It is spelled with a name the alternation
 *  does not carry, and `refuses a name the alternation does not carry` proves
 *  the substitution is what each loop is actually reading. */
const fanOutOver = (entryPoint: string) =>
  `await Promise.allSettled(items.map((i) => ${entryPoint}(env, transport, i)));`;

/** The service-layer entry points a tool can fan out over: the only DAV names
 *  visible from `src/mcp/`, because a tool never sees a tsdav call.
 *
 *  Eleven read entry points, plus the four CalDAV WRITE entry points phase 5
 *  added — `createEvent`, `updateEvent`, `deleteEvent` and `getEventWithEtag`.
 *  Hand-written on purpose, and never derived from the shipped pattern: a list
 *  read out of the very regex it is checked against would agree with that regex
 *  by construction, so dropping a name would drop it from both sides at once
 *  and the loop would stay green. That is the shape of dead gate this project
 *  has already shipped once and had to measure.
 *
 *  The `DAV_FAN_OUT_LIBRARY` half below carries the primitives. The two are
 *  asserted separately, and their UNION is set-equality-checked against the
 *  names actually present in the shipped alternation, so a name added to the
 *  pattern without a matching assertion fails too. */
const DAV_FAN_OUT_SERVICE = [
  "listCalendars",
  "listEvents",
  "searchEvents",
  "getEvent",
  "listAddressBooks",
  "searchContacts",
  "getContact",
  "runDavDiagnosticOutcome",
  "withRediscovery",
  "resolveDavAccount",
  "pagedEvents",
  // Not a write, and on this list for the same reason `withRediscovery` and
  // `resolveDavAccount` are: it costs a real round trip (one PROPFIND at the
  // principal) and it is reachable from `src/mcp/`. WINDOWS entry 60 filed it
  // against this scanner as an open gap, noting it is PARTLY covered by
  // construction -- it wraps `withRediscovery`, so a combinator around THAT
  // still fires -- but that a combinator around this name itself was invisible
  // to every assertion in this file. Naming it closes the entry outright rather
  // than leaving it resting on an implementation detail of its own body.
  //
  // `planCreateTarget`, which entry 60 names alongside it, is deliberately NOT
  // here: it is synchronous, mints a UID and a URL, and issues no request at
  // all. This rule's subject is round trips against one account, so listing a
  // pure function would misstate what it bans.
  "resolveOrganizerAddress",
  // Phase 5's CalDAV write path. Each one ends in one or more DAV round trips
  // that CHANGE the account, so N of them concurrently is N irreversible
  // conversations against one account rather than N reads of it.
  "createEvent",
  "updateEvent",
  "deleteEvent",
  // Held by the set-equality below, NOT by the per-name loop. `getEvent`
  // precedes this in the alternation and is a prefix of it, so the fan-out
  // template matches whether or not this name is in the pattern at all -- its
  // loop assertion is redundant by construction and cannot fail. Written down
  // rather than repaired: the repair is a trailing word boundary on the group,
  // which would make the rule match strictly LESS than it does today, and the
  // Conventions forbid narrowing a rule to tidy an assertion. The set-equality
  // is a real gate on it, so removing the name from the pattern still fails.
  "getEventWithEtag",
  // The COMPOSITE tool-layer entry points phase 5 added (05-REVIEW.md WR-04).
  // Every one of them ends in one or more of the names above, so every one was
  // covered BY ACCIDENT — and this rule's own comment already says what that is
  // worth: "covering a name by accident is how a guarantee quietly leaves when
  // the body is refactored." Naming them is the same move
  // `resolveOrganizerAddress` got one entry up.
  //
  // They are also the layer this rule's `why` says a fan-out is actually written
  // at. `Promise.all(ids.map((id) => buildDeletePreview(...)))` — "preview
  // deleting all of these" — is the shape, and until these were added it matched
  // nothing.
  //
  // **Each of the three `Preview` names is here on its own account, and that is
  // checkable rather than asserted:** `buildPreview` is NOT a prefix of the
  // other two, so none of the three is covered by either of the others and each
  // per-name loop below can genuinely fail. That is the property 05-13 found
  // missing on `getEventWithEtag`, whose loop cannot fail because `getEvent`
  // precedes it and is a prefix of it — do not let that shape back in without
  // writing it down.
  "applyCommit",
  "buildPreview",
  "buildDeletePreview",
  "buildCreatePreview",
  "occurrenceBody",
  // Plan 05-14's third body shaper. It re-reads the resource, decides between
  // the rebuild and the invited-event patch from those bytes, and hands back the
  // one it built — so it ends in a round trip exactly as its two siblings do,
  // and it is named here for the reason they are rather than left resting on
  // `getEventWithEtag` inside its own body.
  "scopelessBody",
  "applyNarrowedDelete",
  "observeDelivery",
  // Phase 6 (SCHED-01). `findFreeSlots` is the new orchestrator: it sweeps EVERY
  // calendar the account has for free/busy time, which is the exact account-wide
  // shape D-84 reintroduces and the sharpest fan-out temptation this tool will
  // face. It is reachable from `src/mcp/`, so it belongs on this list for the
  // same reason `listEvents` does.
  "findFreeSlots",
  // `collectFrom` is now called in a LOOP over collections for the first time.
  // Before phase 6 `pagedEvents` called it exactly once per request, so it
  // carried no fan-out risk and was correctly absent from the alternation; the
  // find-slots loop is what makes wrapping it in a combinator a live temptation
  // (06-RESEARCH.md Pitfall 3, WINDOWS.md entry #60's precedent).
  "collectFrom",
  // Phase 14 (SPIKE-04, SPIKE-02). Both are `dav_diagnose` probes, and both are
  // named HERE as well as among the primitives they end in, for the reason this
  // rule's own comment gives about `resolveOrganizerAddress`: covering a name by
  // accident is how a guarantee quietly leaves when a body is refactored.
  //
  // `runCollectionWriteProbe` is the sharper of the two. It creates, renames,
  // recolours and deletes a throwaway COLLECTION, so a fan-out over it leaves
  // half-finished collections on a real account — and the probe's own cleanup
  // verification, a re-listing of the home set, is exactly what a combinator
  // would race.
  //
  // `runTaskCollectionProbe` is the shape this rule was written for outright: a
  // loop over collections, one `calendar-query` apiece. Both names were added to
  // the alternation BEFORE either function existed, because a name omitted from
  // it is invisible to every assertion in this file — the set-equality included,
  // which operates at the rule level and cannot see inside one.
  //
  // Neither is a prefix of the other, and neither contains any existing entry:
  // they diverge at their fourth character (`runC` / `runT`), and `collectFrom`
  // is not a substring of `runCollectionWriteProbe` because the capitalisation
  // differs. So both per-name loops below can genuinely fail, and the
  // `getEventWithEtag` exception list stays at one.
  "runCollectionWriteProbe",
  "runTaskCollectionProbe",
  // Phase 17's third `dav_diagnose` probe: the property-name reading CALM-07's
  // verdict is waiting on. It is here for the reason its two neighbours are
  // rather than for a new request shape — it ends in `davRequest`, already on the
  // library half below, so it matched BY ACCIDENT before it was written down, and
  // the accident evaporates the first time its body is refactored.
  //
  // The shape it ships is the one this rule was written for outright: a LOOP over
  // four resources issuing one depth-0 `DAV:propname` PROPFIND apiece, which is
  // exactly where a combinator gets written because that is what makes four round
  // trips fast — and the concurrent version returns the same four name lists, so
  // nothing about the answer would reveal the change. Being a READ is what makes
  // it easy to justify speeding up, on `readCollectionState`'s own terms: it
  // writes nothing, so a fan-out costs no calendar state — but four round trips
  // plus discovery and the home listing is already most of one invocation's
  // budget, and iCloud's own per-account ceiling is lower, undocumented and
  // deliberately unmeasured.
  //
  // `propertyNamesInBody` is deliberately NOT here, for the reason every pure
  // reader is left off: it reads element names out of the raw multistatus BODY the
  // probe already holds and issues no request. It named `isDefaultCalendar` as its
  // precedent until 2026-09-26, when CALM-07's withdrawal deleted that function.
  // It carries no manifest disposition either, and that is correct rather than an
  // omission — it is module-private, and the manifest collects `export function`
  // declarations.
  //
  // It reads the BODY rather than the library's parse because that parse could
  // not answer the question at all — measured live on 2026-09-25, and recorded in
  // its own section in `src/dav/diagnose.ts`. The swap changes nothing here: a
  // reader of a string issues no more requests than a reader of an object.
  //
  // Prefix-shadow check RUN against the whole shipped alternation rather than
  // eyeballed: it neither contains nor is contained by any entry.
  // `runCollectionWriteProbe`, `runTaskCollectionProbe` and
  // `runDavDiagnosticOutcome` are the near misses and all three diverge at the
  // fourth character (`runP` / `runC` / `runT` / `runD`), and `propfind` is not
  // contiguous inside it because the capitalisation differs. So its per-name loop
  // below can genuinely fail and the recorded prefix-shadow exception list stays
  // at two.
  "runPropertyNameProbe",
  // Phase 16 (CONW-01). `createContact` is the CardDAV service write: one card
  // per request, conditional on `If-None-Match`, and irreversible in the sense
  // the rule's WRITE paragraph means — "add all of these people" is one
  // sentence, and a half-completed fan-out over it leaves an address book
  // holding some of a list nobody can name.
  //
  // `buildContactCreatePreview` and `applyContactCommit` are the composites, on
  // the same terms as phase 5's eight: each ends in one or more of the names
  // above, so each was covered only BY ACCIDENT, and a body is a refactor away
  // from not doing that.
  //
  // No entry here is a prefix or a substring of any of the three, and none of
  // the three contains any existing entry: `getContact` is not contiguous inside
  // `createContact`, `applyCommit` is not contiguous inside
  // `applyContactCommit`, and neither `buildPreview` nor `buildCreatePreview` is
  // contiguous inside `buildContactCreatePreview`. So all three per-name loops
  // below can genuinely fail, and the `getEventWithEtag` exception list stays at
  // one — which the exception case itself proves rather than takes on trust.
  //
  // `planContactCreateTarget` and `contactUidFromObjectUrl` are deliberately NOT
  // here, on the precedent `planCreateTarget` set at WINDOWS entry 60: both are
  // synchronous, issue no request, and this rule's subject is round trips
  // against one account, so listing a pure function would misstate what it bans.
  // Both carry a WRITTEN disposition in the DAV write manifest instead.
  "createContact",
  "buildContactCreatePreview",
  "applyContactCommit",
  // Phase 16 (CONW-05). The duplicate scan, and the case the rule's own text
  // describes most directly: two probes over one address book is exactly the
  // loop a combinator gets wrapped around, because that is what makes two round
  // trips fast — and the concurrent version returns the same candidates, so
  // nothing about the answer reveals it.
  //
  // It needs no new entry on `DAV_FAN_OUT_LIBRARY`: every request it issues is
  // already named there — `addressBookQuery` for the filtered probe, `propfind`
  // for the enumeration and `addressBookMultiGet` for the bulk read. Read from
  // the pattern rather than assumed.
  //
  // `duplicateFilter` is deliberately NOT here, on the precedent
  // `planContactCreateTarget` set one entry up: it assembles a report body and
  // issues no request, so listing it would misstate what this rule bans. It
  // carries a WRITTEN disposition in the DAV write manifest instead.
  //
  // No entry here is a prefix or a substring of it, and it contains none:
  // `findFreeSlots` shares only `find`, and `getContact` and `createContact` are
  // not contiguous inside it. So its per-name loop below can genuinely fail, and
  // the `getEventWithEtag` exception list stays at one.
  "findDuplicateCandidates",
  // Phase 16 (CONW-02, CONW-06). The two halves of a conditional update: the read
  // that brings back the version stamp, and the overwrite that is conditional on
  // it. Both are named for the reason the WRITE paragraph of the rule's own text
  // gives, and the read is named because it ends in a request too — a fan-out over
  // reads-with-a-version is a fan-out over multi-gets.
  //
  // `getContactWithEtag` JOINS the exception list below rather than adding a
  // per-name loop with teeth: `getContact` precedes it in the alternation and is a
  // prefix of it, so it matched before it was written down, exactly as
  // `getEventWithEtag` does on the calendar tree. That is recorded there rather
  // than repaired here, because the repair — a trailing word boundary on the
  // group — would make the rule match strictly LESS than it does today.
  //
  // `updateContact` has no such defect: no entry is a prefix or a substring of it
  // and it contains none. `getContact` and `createContact` are not contiguous
  // inside it, and `updateEvent` shares only `update`. So its loop can genuinely
  // fail, and the exception list grows by exactly one rather than two.
  "getContactWithEtag",
  "updateContact",
  // Phase 16 (CONW-02). The update PREVIEW composite, and the last name this
  // phase adds. It is here on the COMPOSITE paragraph's terms and it is the
  // strongest instance of them: it ends in TWO guarded names rather than one —
  // `getContactWithEtag` for the card and `findDuplicateCandidates` for the scan —
  // so "covered by accident" is twice as easy to arrive at, and a body that
  // stopped calling either would still match through the other while the
  // guarantee quietly rested on whichever survived the refactor.
  //
  // Its two awaits are serial on purpose and the ORDER is load-bearing rather
  // than incidental: the card is read first so the scan can be told which card to
  // leave out of its own answer. A combinator here would not merely spend two
  // connections at once, it would ask the scan to exclude a url nobody had read
  // yet.
  //
  // No entry here is a prefix or a substring of it and it contains none:
  // `updateContact` shares only the word `update` and not contiguously — this
  // name spells `ContactUpdate` — `getContact` and `createContact` are not
  // contiguous inside it, and neither `buildPreview`, `buildCreatePreview` nor
  // `buildContactCreatePreview` is. So its per-name loop below can genuinely fail
  // and the recorded exception list stays at two.
  "buildContactUpdatePreview",
  // Phase 17 (CALM-04). The collection create, and the first entry on this list
  // whose SUBJECT is a calendar rather than something inside one.
  //
  // The temptation this phase introduces has a shape the earlier ones did not.
  // An account holds nine calendars; once one of them can be made, renamed or
  // removed by name, "tidy up my calendars" is one sentence that means N of
  // them — and the first thing anybody reaching for that writes is a
  // combinator, because that is what makes N round trips fast. It is also the
  // WRITE paragraph's sharper case one level up: a half-completed fan-out over
  // collections leaves whole calendars nobody chose, and on the rename and
  // delete that follow in 17-04 and 17-06, some of them gone.
  //
  // It needs no new entry on `DAV_FAN_OUT_LIBRARY`: the raw request helper this
  // create assembles its extended `MKCOL` through is already named there, added
  // in phase 14. Read from the pattern rather than assumed.
  //
  // `calendarColorForWire` is deliberately NOT here, on the precedent
  // `planCreateTarget` set at WINDOWS entry 60 and `duplicateFilter` followed:
  // it is a synchronous string transformation over an already-validated colour
  // and issues no request, so listing it would misstate what this rule bans. It
  // carries a WRITTEN disposition in the DAV write manifest instead.
  //
  // No entry here is a prefix or a substring of it, and it contains none —
  // checked against the whole shipped alternation rather than eyeballed:
  // `createCalendarObject` is not contiguous inside it (this name spells
  // `CalendarCollection`), `listCalendars` shares only `Calendar`, and
  // `createEvent`, `createContact` and `createVCard` share only `create`. So
  // its per-name loop below can genuinely fail and the recorded prefix-shadow
  // exception list stays at two.
  "createCalendarCollection",
  // CALM-05's rename and recolour, and the FIRST entry on this list whose
  // request target is genuinely caller-supplied: the collection URL arrives
  // inside an opaque id rather than being built from the account's own resolved
  // home set. That changes nothing about why a fan-out is banned here — every
  // one of these is still a socket against the same account — but it is why the
  // home-containment gate drives a real hostile case against this one where the
  // create beside it is exempt.
  //
  // The temptation is the same sentence and slightly worse: "recolour all of
  // these" means N property updates, and a half-completed fan-out leaves an
  // account where some calendars were renamed, some recoloured and some
  // neither, with no answer that can say which.
  //
  // `observedOutcomes` is NOT among them, on `calendarColorForWire`'s
  // precedent: it is a pure comparison between a change the caller asked for and
  // a collection reading the caller already holds, and issues no request, so it
  // carries a WRITTEN disposition in the DAV write manifest instead. It replaced
  // `propstatOutcomes`, which held the same disposition for the same reason and
  // was retired in plan 17-10 — the answer it read carries no property keys at
  // all against the real account, so it reported a fault on every successful
  // write.
  //
  // Prefix-shadow check RUN against all 56 shipped alternation names rather
  // than eyeballed: it neither contains nor is contained by any of them.
  // `updateCalendarObject` is the near miss and is not contiguous inside it —
  // this name spells `CalendarCollection` — and `updateEvent`,
  // `updateContact` and `updateVCard` share only `update`. So its per-name loop
  // below can genuinely fail and the recorded prefix-shadow exception list
  // stays at two.
  "updateCalendarCollection",
  // CALM-06's count entry point: one depth-1 PROPFIND that answers what a
  // collection is bound to and exactly how many member resources go with it.
  //
  // The temptation it creates is the most natural fan-out in this phase, and it
  // is a READ, which is what makes it easy to justify. A previewing caller
  // wanting a member count for every calendar in the home is one sentence —
  // "which of my calendars are empty" — and the first thing anybody reaching
  // for it writes is a combinator over `listCalendars`' result, because that is
  // what makes nine round trips fast. Every one of those nine is a DAV request
  // against the same account, and the concurrent version returns the same
  // counts, so nothing about the answer would reveal the change. A
  // multi-collection count must be serial.
  //
  // `assertCtag` is NOT among them, on `observedOutcomes`' own precedent: it is
  // an assertion over a binding the caller already holds and issues no request,
  // so it carries a WRITTEN disposition in the DAV write manifest instead —
  // the same register `assertEtag`'s neighbouring entry uses.
  //
  // Prefix-shadow check RUN against the whole shipped alternation rather than
  // eyeballed: it neither contains nor is contained by any entry. `getEvent`
  // and `createCalendarCollection` are the near misses and neither is
  // contiguous inside it. So its per-name loop below can genuinely fail and the
  // recorded prefix-shadow exception list stays at two.
  "readCollectionState",
  // The discovery composite CALM-07 added, and the one entry on this list here for
  // the COMPOSITE paragraph's reason ALONE rather than for a new request shape. It
  // outlived CALM-07's withdrawal on 2026-09-26 because the function did — it is
  // the instrument that measured the property absent, and `dav_diagnose` still
  // reports what it reads, so it still issues its two serial PROPFINDs. It
  // ends in `propfind`, which is already on the library half below — so it
  // matched before it was written down, and it matched BY ACCIDENT. The accident
  // is the whole objection: a body that stopped calling `propfind` directly
  // would lose the coverage silently, and the guarantee would have been resting
  // on an implementation detail of the body rather than on a decision anyone
  // recorded.
  //
  // The shape it ships is the sharp one. TWO serial PROPFINDs inside one
  // function — the principal says where the scheduling inbox is, the inbox says
  // which calendar is the account's default — and that is precisely the pair a
  // combinator gets wrapped around, because that is what makes two round trips
  // fast. The concurrent version returns the same URL, so nothing about the
  // answer would reveal the change. And it cannot be raced at all: the second
  // request addresses a URL the first one supplies, so racing them asks about an
  // inbox nobody has resolved yet.
  //
  // **This entry is NOT arm-specific, and a later reader must not remove it as
  // leftover from a branch that did not ship.** A live measurement against the
  // real account chose between two already-decided implementations of this one
  // function, and the arm that did not ship carried ONE request rather than two.
  // That is a weaker temptation and it is registered on exactly the same
  // footing, because which arm shipped is a fact about a checkpoint answer
  // rather than a fact about whether a later session can fan this out. A
  // registration that held against the two-request body and not the one-request
  // body would be a registration resting on which arm somebody remembered.
  //
  // Prefix-shadow check RUN against all 58 shipped alternation names rather than
  // eyeballed: it neither contains nor is contained by any of them.
  // `resolveDavAccount` and `resolveOrganizerAddress` are the near misses and
  // share only `resolve`. So its per-name loop below can genuinely fail and the
  // recorded prefix-shadow exception list stays at two.
  "resolveDefaultCalendarUrl",
  // CALM-06's removal, and the most destructive entry on this list. Every other
  // write here changes something inside a collection; this one removes the
  // collection and everything in it, and neither this server nor the account's
  // owner can put any of it back.
  //
  // The temptation is the most natural multi-collection sentence this server will
  // ever be handed — "get rid of these three" — and the first thing anybody
  // reaching for it writes is a combinator, because that is what makes three
  // round trips fast. Every parallel leg is a destructive request against one
  // account, iCloud's own ceiling is lower than the platform's six and
  // deliberately unmeasured, and a half-completed fan-out leaves whole calendars
  // gone that nobody chose with no answer that can say which.
  //
  // It needs no new entry on `DAV_FAN_OUT_LIBRARY`: `deleteObject`, the helper
  // the removal is issued through, has been on that half since phase 14.
  //
  // Prefix-shadow check RUN against all 59 previously shipped alternation names
  // rather than eyeballed: it neither contains nor is contained by any of them.
  // `deleteCalendarObject` is the near miss and is not contiguous inside it —
  // this name spells `CalendarCollection` — and `createCalendarCollection`,
  // `updateCalendarCollection`, `deleteEvent` and `deleteObject` share only a
  // prefix or a verb. So its per-name loop below can genuinely fail and the
  // recorded prefix-shadow exception list stays at two.
  "deleteCalendarCollection",
  // The delete's TOOL-LAYER preview composite, on the COMPOSITE paragraph's own
  // terms and for two calls rather than one: it ends in `resolveDavAccount` —
  // which is what hands it the home set the confirmation seals, and which used to
  // be what made CALM-07's refusal local — and in `readCollectionState`, which is
  // what makes the count exact. Two ways to be covered by accident, and
  // the accident would be resting on whichever of the two a later body still
  // happened to call.
  //
  // The fan-out it invites is the one that reads as harmless: a preview writes
  // nothing, so "show me what I'd lose on each of these" feels free. It is not
  // free — it is one depth-1 PROPFIND per calendar against the same account,
  // which is the same budget the delete itself spends.
  //
  // Prefix-shadow check RUN: it does NOT contain `buildDeletePreview`
  // contiguously (this name spells `buildCollectionDeletePreview`), does not
  // contain `buildPreview` or `buildCreatePreview`, and is contained by nothing.
  "buildCollectionDeletePreview",
  // The delete's tool-layer COMMIT composite, and the sharpest composite on this
  // list: it ends in `readCollectionState` AND `deleteCalendarCollection`, so a
  // body that stopped calling either would still match through the other and the
  // guarantee would rest on which one survived.
  //
  // Its three requests are serial on purpose and the order is load-bearing
  // twice: the binding re-read decides whether the removal is sent at all, and
  // the fresh look is the only evidence this project accepts that the removal
  // landed. Racing either with the removal would be asking about a collection
  // nobody has decided to delete yet, or looking before the delete arrived.
  //
  // Prefix-shadow check RUN: it does NOT contain `applyCommit` contiguously
  // (this name spells `applyCollectionCommit`), does not contain
  // `applyContactCommit` or `applyNarrowedDelete`, and is contained by nothing.
  "applyCollectionCommit",
];

/** The request primitive and the tsdav standalone helpers: what a "just do them
 *  all" edit inside `src/dav/` reaches for.
 *
 *  Read helpers, plus the three tsdav WRITE helpers phase 5's service layer
 *  calls through. Before this list existed, only the two names appearing in the
 *  rule's violating sample were asserted at all — the other ten were on the
 *  alternation and covered by nothing, which is the same invisibility the write
 *  extension exists to close, one layer down. */
const DAV_FAN_OUT_LIBRARY = [
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
  "createCalendarObject",
  "updateCalendarObject",
  "deleteCalendarObject",
  // Phase 14's three, added BEFORE the call sites that use them existed.
  // `makeCalendar` is the collection-creation helper (it issues MKCALENDAR
  // through `davRequest`), `davRequest` is the raw request helper the
  // property-update step has to assemble by hand because tsdav ships no
  // PROPPATCH helper, and `deleteObject` is the collection removal.
  //
  // `calendarQuery`, which the to-do probe calls, is deliberately NOT repeated:
  // it went on this list for the event listing and appears in the alternation
  // exactly once. A second entry would break the set-equality below, which is
  // the check that would otherwise catch the name being dropped.
  //
  // None of the three is a prefix or a substring of any existing entry, and no
  // existing entry is a prefix or substring of them — in particular
  // `deleteCalendarObject` neither contains `deleteObject` nor is contained by
  // it, because the two words are not contiguous in it. So all three per-name
  // loops below can genuinely fail.
  "makeCalendar",
  "davRequest",
  "deleteObject",
  // Phase 16's one. tsdav ships `createVCard` as the CardDAV object-creation
  // helper — verified against the installed package's own exported surface
  // rather than taken from prose — and it is the primitive `createContact` ends
  // in. It is not a prefix or a substring of any entry above it and none is a
  // substring of it, so its per-name loop can genuinely fail.
  "createVCard",
  // Phase 16's second, CONW-02. tsdav ships `updateVCard` as the CardDAV object
  // overwrite — verified against the installed package's own exported surface
  // rather than taken from prose — and it is the primitive `updateContact` ends
  // in. It is the sharper of the two on this list for the reason the write
  // paragraph above gives: a create aimed at the wrong origin leaks, and an
  // overwrite aimed at the wrong origin also REPLACES what it found there. It is
  // not a prefix or a substring of any entry above it — `createVCard` shares only
  // `VCard`, which is not a leading match either way — so its loop can genuinely
  // fail.
  "updateVCard",
];

/** The names actually present in the shipped rule's final alternation group.
 *
 *  Mechanical, and it fails loudly rather than quietly: an extraction that came
 *  back empty or garbled produces a set that cannot equal the hand-written
 *  union, so the assertion using it reports a mismatch instead of passing on a
 *  vacuous comparison. */
function alternationNamesOf(pattern: RegExp): string[] {
  const source = pattern.source;
  const open = source.lastIndexOf("(?:");
  const close = source.lastIndexOf(")");
  if (open < 0 || close < open) {
    throw new Error("no trailing alternation group found in the rule's source");
  }
  return source.slice(open + "(?:".length, close).split("|");
}

/** Exclusion disabled, so a rule's reach over a real tree can be compared with
 *  and without the skip-list. */
const NO_EXCLUSIONS = { excluded: new Set<string>() };

// Source text, read off the repository rather than restated here. The write-module
// constraint below needs two kinds of it: the DAV modules, so a green pass means
// the SHIPPED tree passes rather than a fixture, and the scanner itself, so the
// production call site can be pinned by its own text.
//
// `?raw` rather than `node:fs`, following test/dav-home-containment.test.ts:
// this project deliberately carries no Node type package, and a `node:fs` import
// in a .ts file fails typecheck. Vite's suffix inlines the file's text at build
// time instead, at the cost of a suppression — the suffix has no ambient
// declaration because `vite/client` is not in tsconfig's `types`. The
// suppression is proven non-vacuous by `tsc` itself, which errors on a
// `@ts-expect-error` that suppresses nothing.
//
// The DAV tree is GLOBBED rather than listed file by file so a module declared
// in the manifest later is picked up without editing this line, and
// `rawSourceOf` throws rather than returning an empty string when a declared
// module is not globbed — an empty string would silently report every manifest
// name as stale.
// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here; see above.
const RAW_SOURCES: Record<string, string> = import.meta.glob(
  ["../src/dav/*.ts", "../scripts/forbidden-tokens.mjs"],
  { query: "?raw", import: "default", eager: true },
);

/** The text of one repo-relative file, or a throw naming what was not globbed. */
function rawSourceOf(repoRelative: string): string {
  const text = RAW_SOURCES[`../${repoRelative}`];
  if (text === undefined || text.length === 0) {
    throw new Error(`no raw source globbed for ${repoRelative}`);
  }
  return text;
}

describe("the ban list itself", () => {
  it("gives every rule a non-empty reason, because the hook prints it on rejection", () => {
    expect(FORBIDDEN.length).toBeGreaterThan(0);
    for (const rule of FORBIDDEN) {
      expect(rule.why, `rule ${rule.id} has no reason`).toBeTruthy();
      expect(rule.why.trim().length).toBeGreaterThan(20);
    }
  });

  it("gives every rule a distinct id, so a violation names which rule fired", () => {
    const ids = FORBIDDEN.map((rule) => rule.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("the patterns have teeth", () => {
  // Matched against in-memory strings rather than fixture files. A fixture file
  // carrying a banned token would itself need excluding from the scan, which is
  // the self-exclusion problem all over again.
  const violatingSamples: Record<string, string> = {
    "tls-upgrade-call": "const upgraded = await socket.startTls();",
    "tls-upgrade-mode": 'connect(addr, { secureTransport: "starttls" });',
    "cleartext-imap-port": "connect({ hostname: host, port: 143 });",
    "smtp-submission-port": "connect({ hostname: host, port: 587 });",
    "host-with-banned-port": 'const relay = "smtp.mail.me.com:465";',
    "mail-sending-library": 'import { createTransport } from "nodemailer";',
    "secret-binding-in-log-call": "console.log(`sending`, env.APPLE_APP_PASSWORD);",
    "logging-on-the-credential-path": "console.debug(commandLine);",
    // A debug line in src/mcp/ or src/auth/ — outside src/mail/, so the rule
    // above never sees it, and naming no secret, so the rule above that one
    // never sees it either. That pair of blind spots is what this rule closes.
    "logging-anywhere-under-src": 'console.log("handler reached", requestId);',
    // The same call one step worse: the whole environment object, which carries
    // all three secrets without any of them being written down.
    "env-object-in-log-call": 'console.warn("diagnose env", env);',
    // The same leak after the credentials move into the grant. The props read
    // off the execution context hold the Apple ID and the app-specific
    // password, and this line names neither. It is the debug line a
    // contributor would really write while wiring the handler, which is why it
    // is the sample: no binding name, no environment object, so neither rule
    // above sees it.
    "props-object-in-log-call": 'console.log("grant reached the handler", ctx.props);',
    // A fan-out around the choke-point. Written with an arrow function on
    // purpose: the parenthesis pair in `()` is exactly what a naive
    // "no closing paren between them" pattern would trip over.
    "concurrent-connect": "await Promise.all(folders.map(() => runOver(connectImap())));",
    // The same fan-out one layer up, and the shape a contributor would actually
    // write: nobody wraps a combinator around the raw connect helper, because
    // nothing but the orchestrator calls it. Arrow function again, for the same
    // reason as the rule above — the `()` is what a naive span trips over.
    "concurrent-session":
      "await Promise.all(refs.map((ref) => withMailSession(env, gate, ref.mailbox, ref.uidValidity, one)));",
    // A fetch item list hoisted into a constant, written without the peeking
    // form. This is the shape with the worst blast radius: the page-listing
    // path sends one of these per page.
    "non-peeking-fetch-item":
      'const ITEMS = "(UID FLAGS INTERNALDATE RFC822.SIZE BODY[])";',
    // The same fan-out shape as the two rules above, one protocol over. Arrow
    // function again, for the same reason: the `()` is what a naive
    // paren-bounded span trips over.
    //
    // WRITE-shaped, and deliberately so. The read half was never the dangerous
    // one: an account-wide sweep over reads was withdrawn because it could not
    // be repaired by making it concurrent, and a read that loses the race just
    // returns a worse answer. A sweep over WRITES cannot be repaired at all —
    // each request in it changes the user's calendar, so a half-completed
    // fan-out leaves a state nobody chose and no retry can describe. Naming a
    // service write entry point keeps the rule-level set-equality guard
    // exercising the half phase 5 added rather than only the half it inherited.
    //
    // The transport is NOT spelled `davFetch` here, for the reason `fanOutOver`
    // gives: that name is itself on the alternation, so a sample carrying it
    // would match with every write name deleted again and would prove nothing
    // about the extension. This sample matches through `deleteEvent` alone.
    "dav-concurrent-request":
      "await Promise.all(refs.map((r) => deleteEvent(env, transport, r.eventId, r.etag)));",
    // One boolean that turns account discovery into a fan-out over every
    // collection fetching every object inside it.
    "dav-eager-load":
      "const account = await createAccount({ account: base, loadCollections: true });",
    // The host-timezone-dependent conversion. Silently wrong times, never an
    // error, and the test pool's zone is not production's.
    "ical-jsdate": "const start = event.startDate.toJSDate();",
    // A test that wants to run as user B and reaches for the shortest way to do
    // it: writing B's address onto the shared environment object. Member
    // assignment, because that is the form a contributor types first. The
    // object is shared by every test in the file, so the next test runs as B
    // without saying so. The right way is a fresh copy with both account
    // fields overridden, which is what the two-user fixture does.
    "env-assignment": 'env.APPLE_ID = "user-b@example.invalid";',
    // A store key built from a prefix constant with the token id straight
    // after it and no user segment in between. This is the contributor mistake
    // the rule is aimed at, and it is an honest one: the jti is unique, so the
    // key looks unique, and the code works perfectly for one user. It is only
    // wrong once a second person exists — at which point any signed-in caller
    // who knows a jti can name the key holding somebody else's pending write.
    // Every one of the four key expressions in this project was written this
    // way before Phase 10 reshaped them.
    "store-key-without-a-user": "const key = `${CONFIRM_KEY_PREFIX}${jti}`;",
    // The one-time reservation keyed on the confirmation instead of on the
    // caller presenting it. A one-word edit that reads as MORE correct — the
    // slot belongs to the token, surely — and which quietly removes the second
    // of audit row T1's two layers. The two values are equal in every
    // execution this project can produce, so no test can separate them; this
    // rule is the only thing that can.
    "confirm-reserve-keyed-on-the-token":
      "await reserveConfirmation(env.CONFIRM_KV, payload.u, payload.j, payload.x);",
    // The library's record sweeper, called from a scheduled handler. Written as
    // the housekeeping line a contributor would actually reach for: it reads as
    // tidying, and the thing it quietly does is delete every grant whose client
    // record has gone — the forced logout LIFE-01 removed.
    "expired-record-sweeper":
      "await purgeExpiredData(env.OAUTH_KV, { gracePeriodSeconds: 0 });",
    // Phase 13, CUT-01. Spelled verbatim here, which is safe for the same
    // reason the props and password samples below are: this file is skipped by
    // path for every rule. The rule it samples was a COUNT until the binding it
    // counted the readers of was deleted; zero became the correct number, so the
    // missing arm could never fire and the count became a ban.
    "mail-secret-read": "  const appleId = env.APPLE_ID;",
    // Phase 17, D-15. Spelled verbatim here for the same reason every sample
    // above is: this file is skipped by PATH for every rule, and it is the only
    // file under test/ that is. The shape is the one a future session would
    // actually write -- the obvious method for the obvious job, reached for
    // because RFC 4791 names it and the library ships a helper for it.
    "mkcalendar-method":
      'const made = await davRequest({ url, init: { method: "MKCALENDAR" } });',
    // And the helper itself, at the import that makes it reachable. An import
    // rather than a call site on purpose: the import is where the decision is
    // actually taken, and it is one line earlier than the call the rule would
    // otherwise first see.
    "tsdav-make-calendar": 'import { makeCalendar } from "tsdav";',
  };

  it("covers every rule with a known-violating sample", () => {
    // Guards the guard: a rule added without a sample would otherwise be
    // untested, and an untested pattern that matches nothing looks identical to
    // a tree with nothing to find.
    expect(Object.keys(violatingSamples).sort()).toEqual(
      FORBIDDEN.map((rule) => rule.id).sort(),
    );
  });

  for (const rule of FORBIDDEN) {
    it(`rule "${rule.id}" matches a known violation`, () => {
      const sample = violatingSamples[rule.id];
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(sample), `pattern for ${rule.id} matched nothing`).toBe(true);
    });
  }

  it("does not fire the store-key rule on any shape Phase 10 actually shipped", () => {
    // The five shapes that exist under src/ today. Four are the key
    // expressions ISO-06 reshaped; the fifth is the MIME boundary constant in
    // the message-assembly module, which is the near-miss this rule has to
    // stay off. The store-word filter is what keeps that one clean, and it
    // matters that it is the filter doing the work and not a path exclusion:
    // EXCLUDED skips a file for EVERY rule, so excluding the module that
    // assembles a message would silently drop its logging, fan-out and write
    // rules too. The assertion below pins that it is NOT excluded.
    const rule = FORBIDDEN.find((r) => r.id === "store-key-without-a-user")!;
    const fires = (sample: string): boolean =>
      new RegExp(rule.pattern.source, rule.pattern.flags).test(sample);

    for (const sample of [
      // src/staging/r2.ts — the binding side
      "  const key = `${STAGING_PREFIX}${userId}/${segment}-${safe}-${nowMs}`;",
      // src/staging/presign.ts — the presigned side
      "  return `${STAGING_PREFIX}${userId}/${PRESIGNED_KEY_STEM}-${segment}-${nowMs}`;",
      // src/confirm.ts
      "  const key = `${CONFIRM_KEY_PREFIX}${userId}:${jti}`;",
      // src/dav/discovery.ts
      "  return `${DAV_CACHE_KEY_PREFIX}${userId}:${service}`;",
      // src/mail/compose.ts — a MIME boundary, not a store key at all
      "    const candidate = `${BOUNDARY_PREFIX}${crypto.randomUUID()}`;",
      // The two member-access spellings of the same id, both permitted.
      "  const key = `${STAGING_PREFIX}${principal.userId}/x`;",
      "  const key = `${STAGING_PREFIX}${actor.userId}/x`;",
      // A correct key reached through a deeper path. Nothing on the tree is
      // written this way today, and that is exactly why it needs a row: when
      // the chain was bounded at one, this FIRED. A false positive here is not
      // one refused line — `.husky/pre-commit` runs under `set -e`, so it
      // refuses every commit in the repository, including unrelated work.
      "  const key = `${STAGING_PREFIX}${ctx.actor.userId}/x`;",
      "  const key = `${CONFIRM_KEY_PREFIX}${a.b.c.userId}:${jti}`;",
    ]) {
      expect(fires(sample), `false-positived on ${sample}`).toBe(false);
    }

    // The near-miss stays inside every other rule's reach.
    expect(EXCLUDED.has("src/mail/compose.ts")).toBe(false);
  });

  it("fires the store-key rule when anything at all sits between the prefix and the id", () => {
    // The rule's own first paragraph says the user id must come straight after
    // the prefix constant and that nothing may sit between the two. The
    // lookahead used to open with `\s*`, which is OUTSIDE the interpolation and
    // so matched literal template characters — both rows below passed the scan
    // while building a key with a space or a newline in the middle of it. No
    // cross-user leak, since the id is still there, but the rule proved less
    // than it claimed, and a rule believed to prove more than it does is worse
    // than one whose limits are written down. These rows are what keeps the
    // gap shut: put the `\s*` back and both go red.
    const rule = FORBIDDEN.find((r) => r.id === "store-key-without-a-user")!;
    const fires = (sample: string): boolean =>
      new RegExp(rule.pattern.source, rule.pattern.flags).test(sample);

    for (const sample of [
      "const key = `${CONFIRM_KEY_PREFIX} ${userId}:${jti}`;",
      "const key = `${CONFIRM_KEY_PREFIX}\n${userId}:${jti}`;",
      "const key = `${STAGING_PREFIX} ${principal.userId}/x`;",
    ]) {
      expect(fires(sample), `missed a gap before the id in ${sample}`).toBe(true);
    }
  });

  it("does not fire on the port and transport mode this project actually uses", () => {
    const permitted = 'connect({ hostname: h, port: 993 }, { secureTransport: "on" });';
    for (const rule of FORBIDDEN) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(permitted), `rule ${rule.id} false-positived`).toBe(false);
    }
  });

  it("catches a bare fetch item written inline in the command, not only hoisted", () => {
    // The item list is written both ways in this codebase — hoisted into a
    // constant, and interpolated into the command. The rule carries one anchor
    // for each, and the sample above only exercises the first. Without this,
    // dropping the command-shaped anchor would leave the suite green.
    const inline = "await send(channel, tag, `UID FETCH ${uid} (UID FLAGS BODY[])`);";
    const rule = FORBIDDEN.find((r) => r.id === "non-peeking-fetch-item")!;
    const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
    expect(fresh.test(inline)).toBe(true);
  });

  it("keeps looking past an interpolated call in the command", () => {
    // The span is bounded by the statement and the line, not by the next
    // closing parenthesis — the same choice the socket-level concurrency rule
    // makes and for the same reason. An interpolation that calls anything at
    // all puts a `)` between the anchor and the item, and a paren-bounded span
    // would stop there and report nothing. Found by mutation: swapping the
    // bound for `[^)]` left every other assertion in this file green.
    const interpolated = "const cmd = `UID FETCH ${ref.at(0)} (UID FLAGS BODY[])`;";
    const rule = FORBIDDEN.find((r) => r.id === "non-peeking-fetch-item")!;
    const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
    expect(fresh.test(interpolated)).toBe(true);
  });

  it("catches a lowercase fetch item, because the protocol is case-insensitive", () => {
    // A server treats a lowercase item name as the same item, so a lowercase
    // spelling marks the same page read. Without this the `i` flag could be
    // dropped and the suite would stay green.
    const lower = 'const items = "(uid flags body[])";';
    const rule = FORBIDDEN.find((r) => r.id === "non-peeking-fetch-item")!;
    const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
    expect(fresh.test(lower)).toBe(true);
  });

  it("catches the RFC822 spelling of the same seen-flag side effect", () => {
    // RFC 3501 makes RFC822 and RFC822.TEXT functionally equivalent to the bare
    // body item, side effect included. A rule that caught one spelling and not
    // its synonym would give false assurance, which is worse than no rule.
    const rule = FORBIDDEN.find((r) => r.id === "non-peeking-fetch-item")!;
    for (const sample of [
      'const items = "(UID FLAGS RFC822)";',
      'const items = "(UID RFC822.TEXT)";',
    ]) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(sample), `missed ${sample}`).toBe(true);
    }
  });

  it("excuses the RFC822 sub-items that fetch no body and set no flag", () => {
    // RFC822.SIZE is in this project's own permitted item list and RFC822.HEADER
    // is the peeking-equivalent header fetch. Banning either would ban the
    // command the rule is protecting.
    const rule = FORBIDDEN.find((r) => r.id === "non-peeking-fetch-item")!;
    for (const sample of [
      'const items = "(UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[])";',
      'const items = "(RFC822.HEADER)";',
    ]) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(sample), `false-positived on ${sample}`).toBe(false);
    }
  });

  it("keeps the negative lookahead load-bearing, not decorative", () => {
    // Measured, not assumed: with the item spelled `BODY[` and nothing else
    // permitted between the name and the bracket, a lookahead against a
    // dot-prefixed suffix can never fire, and deleting it leaves every other
    // assertion green. The qualifier group is what gives the lookahead
    // something to refuse — this asserts the pair works together.
    const rule = FORBIDDEN.find((r) => r.id === "non-peeking-fetch-item")!;
    const withoutLookahead = new RegExp(
      rule.pattern.source.replace("(?!\\.PEEK)", ""),
      rule.pattern.flags,
    );
    const peeking = 'const items = "(UID FLAGS BODY.PEEK[])";';
    expect(new RegExp(rule.pattern.source, rule.pattern.flags).test(peeking)).toBe(
      false,
    );
    expect(
      withoutLookahead.test(peeking),
      "the lookahead removes no match, so it is dead code",
    ).toBe(true);
  });

  it("catches a fan-out around the over-a-stream session variant too", () => {
    // `withMailSessionOver` opens a session over an already-open stream, and N
    // of those is still N conversations against one connection budget. The
    // sample above exercises only the socket-opening variant, so without this a
    // rule narrowed to the exact name would leave the suite green.
    const fanOut =
      "await Promise.any(names.map((n) => withMailSessionOver(sock, env, gate, n, null, one)));";
    const rule = FORBIDDEN.find((r) => r.id === "concurrent-session")!;
    const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
    expect(fresh.test(fanOut)).toBe(true);
  });

  it("does not fire on a single session call with no combinator around it", () => {
    // The permitted form, and the one every mail tool in this phase writes. A
    // rule that could not tell this from a fan-out would ban the orchestrator
    // it exists to protect.
    const permitted = "return withMailSession(env, gate, mailbox, uidValidity, fn);";
    for (const rule of FORBIDDEN) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(permitted), `rule ${rule.id} false-positived`).toBe(false);
    }
  });

  it("does not fire on a fetch item list that uses the peeking form", () => {
    // The permitted form, byte-for-byte what FETCH_ITEMS holds in
    // src/mail/service.ts.
    const permitted =
      'const ITEMS = "(UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[])";';
    for (const rule of FORBIDDEN) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(permitted), `rule ${rule.id} false-positived`).toBe(false);
    }
  });

  it("does not fire on reading the server's own reply key", () => {
    // The discriminator that makes the rule above anchored rather than
    // spelling-based: a peeking fetch comes BACK from the server under a key
    // spelled without the peek, so src/mail/service.ts must look that key up.
    // A rule keyed on the spelling alone would ban reading the reply to the
    // very command it protects.
    const permitted = 'const body = items.get("BODY[]");';
    const rule = FORBIDDEN.find((r) => r.id === "non-peeking-fetch-item")!;
    const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
    expect(fresh.test(permitted)).toBe(false);
  });

  it("does not mistake a clock-shaped string for a banned port", () => {
    const innocent = 'const label = "12:25"; const other = "07:465";';
    const rule = FORBIDDEN.find((r) => r.id === "host-with-banned-port")!;
    const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
    expect(fresh.test(innocent)).toBe(false);
  });

  it("scopes each DAV rule to the DAV tree, driven through the scanner's own matcher", () => {
    // Not `rule.scope === "src/dav/"`: that would restate the scanner's
    // prefix logic here and pass even if `matchRule` stopped honouring scope
    // at all. Driving the real matcher is what makes the directory prefix
    // proven load-bearing rather than merely declared.
    for (const id of DAV_RULE_IDS) {
      const rule = FORBIDDEN.find((r) => r.id === id)!;
      const index = FORBIDDEN.indexOf(rule);
      const sample = violatingSamples[id]!;
      expect(
        matchRule(rule, index, "src/dav/calendar.ts", sample).length,
        `${id} did not fire inside its own tree`,
      ).toBeGreaterThan(0);
      expect(
        matchRule(rule, index, "src/mail/service.ts", sample),
        `${id} escaped its scope`,
      ).toEqual([]);
    }
  });

  it("does not fire on the seconds-since-epoch accessor, which is the permitted form", () => {
    // The rule bans the conversion whose result depends on the host zone. The
    // epoch accessor is what src/dav/icalendar.ts uses once a zone has been
    // resolved, so banning both would ban the fix along with the bug.
    const permitted = "const seconds = resolved.toUnixTime();";
    const rule = FORBIDDEN.find((r) => r.id === "ical-jsdate")!;
    const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
    expect(fresh.test(permitted)).toBe(false);
  });

  it("catches an orchestrator-level fan-out written outside the DAV tree", () => {
    // 03-REVIEW.md WR-03. It is the shape a contributor would actually write: a
    // tool has an array of identifiers and reaches for the entry point it
    // imported, because a tsdav call is not in scope there and never will be —
    // and with the rule scoped to src/dav/ over library names, this exact line
    // matched nothing at all.
    //
    // Driven through the scanner's own matcher rather than a bare regex test,
    // so the scope widening is proven load-bearing rather than merely declared
    // — a rule reverted to `src/dav/` fails here rather than passing quietly.
    const rule = FORBIDDEN.find((r) => r.id === "dav-concurrent-request")!;
    const index = FORBIDDEN.indexOf(rule);
    const fanOut =
      "const events = await Promise.all(ids.map((id) => getEvent(env, davFetch, id)));";
    expect(
      matchRule(rule, index, "src/mcp/tools/calendar.ts", fanOut).length,
      "the DAV fan-out rule does not reach src/mcp/tools/, which is the layer a fan-out is written at",
    ).toBeGreaterThan(0);
    // The library half, in its own tree, spelled out here rather than reusing
    // the rule's violating sample. The sample is now service-shaped, so reusing
    // it would leave the tsdav shape with no matcher-driven assertion anywhere
    // and the loss would be invisible: this test would keep passing, on the
    // wrong evidence.
    expect(
      matchRule(
        rule,
        index,
        "src/dav/calendar.ts",
        "await Promise.all(calendars.map((c) => fetchCalendarObjects({ calendar: c, fetch: davFetch })));",
      ).length,
      "widening the scope lost the rule's reach over its own tree",
    ).toBeGreaterThan(0);

    // And the COMPOSITE half (05-REVIEW.md WR-04). "Preview deleting all of
    // these" is one sentence, and this is the line it turns into — written in
    // the very file the seven names live in. It names no service entry point
    // and no tsdav call, so before those names were added it matched nothing:
    // the previous two assertions here would both stay green with the whole
    // composite half absent, which is why this one is spelled out separately.
    expect(
      matchRule(
        rule,
        index,
        "src/mcp/tools/calendar.ts",
        "const previews = await Promise.all(ids.map((id) => buildDeletePreview(transport, refOf(id), id, scope)));",
      ).length,
      "the rule does not reach the composite tool-layer entry points, which is the layer its own reason says a fan-out is written at",
    ).toBeGreaterThan(0);

    // Phase 6's own orchestrator. `findFreeSlots` sweeps every calendar the
    // account has, so a "check them all at once" edit is the exact fan-out D-84
    // reintroduces the temptation for — exercised here through the same matcher
    // so the extension is proven load-bearing rather than only declared.
    expect(
      matchRule(rule, index, "src/mcp/tools/calendar.ts", fanOutOver("findFreeSlots"))
        .length,
      "the rule does not reach findFreeSlots, phase 6's account-wide free/busy orchestrator",
    ).toBeGreaterThan(0);
  });

  it("names every DAV service entry point a tool can fan out over, read and write alike", () => {
    // The alternation's outermost layer, asserted name by name. Without this,
    // dropping any single entry point from the pattern leaves every other
    // assertion in this file green — the rule-level set-equality guard
    // included, because that guard operates at the RULE level and cannot see
    // inside one. This is the same both-directions discipline the count
    // constraints below already use, applied to the inside of one pattern.
    //
    // Phase 5's four write entry points are on this list for a sharper reason
    // than the reads. `Promise.all(ids.map(deleteEvent))` is the single most
    // tempting fan-out this project will ever be offered — "clear my calendar
    // for August" is one sentence — and until those names were added it passed
    // the scan outright.
    //
    // The eight COMPOSITE names are on it for the reason the rule's own comment
    // gives about `resolveOrganizerAddress`: each was covered only because its
    // body happens to call a guarded name, and a body is a refactor away from
    // not doing that.
    const rule = FORBIDDEN.find((r) => r.id === "dav-concurrent-request")!;
    expect(
      DAV_FAN_OUT_SERVICE.length,
      "eleven read entry points, phase 5's four writes, the organiser resolution WINDOWS 60 filed, the eight composite tool-layer entry points 05-REVIEW.md WR-04 filed plus 05-14's scopelessBody, phase 6's findFreeSlots orchestrator and its looped collectFrom, phase 14's two dav_diagnose probes — runCollectionWriteProbe, whose fan-out would leave half-finished collections on a real account and race its own cleanup check, and runTaskCollectionProbe, a loop over collections issuing one calendar-query apiece — and phase 16's three: the CardDAV write createContact, plus the two composites buildContactCreatePreview and applyContactCommit, which end in it and were therefore covered only by accident. planContactCreateTarget and contactUidFromObjectUrl are NOT among them: both are synchronous and issue no request, so they carry a written manifest disposition instead. CONW-05 adds a fourth from phase 16, findDuplicateCandidates — the duplicate scan, and the case this rule's own text describes most directly: two probes over one address book is exactly the loop a combinator gets wrapped around, and the concurrent version returns the same candidates, so nothing about the answer reveals it. duplicateFilter is NOT among them either, on planContactCreateTarget's precedent: it assembles a report body and issues no request. CONW-02 and CONW-06 add the two halves of a conditional update — getContactWithEtag, the read that brings back the version stamp out of the same multi-status the plain read already issued, and updateContact, the overwrite that is conditional on it. Their read and their write are two SERIAL awaits and never a pair to be raced: racing them asks the server about a version nobody has read yet. CONW-02 adds one more composite, buildContactUpdatePreview, and it is the strongest instance of the COMPOSITE paragraph above: it ends in TWO guarded names rather than one, the read-with-a-version and the duplicate scan, so it would be covered only by accident through whichever of the two a later body still happened to call. Its two awaits are serial on purpose and the order is load-bearing, because the card is read first so the scan can be told which card to leave out of its own answer. Phase 17 (CALM-04) adds createCalendarCollection, the collection create and the first entry whose subject is a calendar rather than something inside one: once a calendar can be made, renamed or removed by name, 'tidy up my calendars' is one sentence that means N of them, and a half-completed fan-out over collections leaves whole calendars nobody chose. calendarColorForWire is NOT among them, on planCreateTarget's precedent: it is a synchronous string transformation over an already-validated colour and issues no request, so it carries a written manifest disposition instead. Phase 17 (CALM-05) adds updateCalendarCollection, the rename and recolour, and the first entry on this list whose request target is genuinely CALLER-SUPPLIED rather than built from the account's own resolved home set -- which is why the home-containment gate drives a real hostile case against it where the create beside it is exempt. observedOutcomes is NOT among them, on calendarColorForWire's own precedent: it is a pure comparison between a change the caller asked for and a collection reading the caller already holds, issues no request, and replaced propstatOutcomes when plan 17-10 retired that reader, so it carries a written manifest disposition instead. Phase 17 (CALM-06) adds readCollectionState, the count entry point, and it is the most natural fan-out this phase introduces precisely because it is a READ: 'which of my calendars are empty' is one sentence that means one depth-1 PROPFIND per calendar, the combinator is what makes nine round trips fast, and the concurrent version returns the same counts so nothing about the answer would reveal it. assertCtag is NOT among them, on observedOutcomes' own precedent: it is an assertion over a binding the caller already holds and issues no request, so it carries a written manifest disposition instead. Phase 17 adds resolveDefaultCalendarUrl, the discovery composite, and it is here for the COMPOSITE paragraph's reason alone: it ends in propfind, so it matched by ACCIDENT before it was written down, and the accident evaporates the first time its body is refactored. Its shipped shape is two SERIAL PROPFINDs in one function -- principal, then scheduling inbox -- which is the pair a combinator gets wrapped around because that is what makes two round trips fast, and the concurrent version returns the same URL so nothing about the answer would reveal it. The entry is deliberately NOT arm-specific: the arm a live measurement did not choose carried one request rather than two, and registering only against the sharper body would rest the guarantee on which arm a reader remembered. It also outlived the requirement it arrived for: CALM-07 was withdrawn on 2026-09-26 because the property it asks for is absent everywhere it can be asked, and the function was kept as the instrument of that measurement, so it is still two serial PROPFINDs and still the pair a combinator gets wrapped around. isDefaultCalendar WAS on this list as a NOT-among-them, on assertCtag's precedent, and it is not mentioned any more because the function was deleted with the requirement -- a written exclusion for a name that does not exist is a reason no reader can check. Phase 17 (CALM-06) adds the delete's three: deleteCalendarCollection, the DAV entry point, and the two TOOL-LAYER composites buildCollectionDeletePreview and applyCollectionCommit. The entry point is the most destructive name on this list -- every other write here changes something inside a collection and this one removes the collection and everything in it -- and 'get rid of these three' is the most natural multi-collection sentence this server will ever be handed, which is exactly where a combinator gets written. The two composites are on the COMPOSITE paragraph's terms and each ends in more than one guarded name: the preview in resolveDavAccount and readCollectionState, the commit in readCollectionState AND deleteCalendarCollection, so each would be covered only by accident and by whichever call a later body happened to keep. No new library primitive is needed: deleteObject, the helper the removal is issued through, has been on the library half since phase 14. Phase 17 adds runPropertyNameProbe, the third dav_diagnose probe and the instrument CALM-07's verdict was taken on: four resources, one depth-0 DAV:propname PROPFIND apiece, in a loop -- which is precisely where a combinator gets written, because that is what makes four round trips fast, and the concurrent version returns the same four property-name lists so nothing about the answer would reveal the change. It needs no new library primitive: davRequest, the raw helper it assembles the propname body through, has been on the library half since phase 14. propertyNamesInBody is NOT among them, for the reason every pure reader is left off -- it reads element names out of the raw multistatus BODY the probe already holds and issues no request -- and unlike that one it carries no manifest disposition either, correctly, because it is module-private and the manifest collects export function declarations",
    ).toBe(43);
    for (const entryPoint of DAV_FAN_OUT_SERVICE) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(
        fresh.test(fanOutOver(entryPoint)),
        `${entryPoint} is not named in the alternation`,
      ).toBe(true);
    }
  });

  it("names every DAV library primitive a src/dav/ edit can fan out over, read and write alike", () => {
    // The alternation's innermost layers, asserted name by name for the same
    // reason as the loop above. Twelve of these were on the alternation and
    // covered by nothing at all before this loop existed — the rule's single
    // violating sample named two of them, and a sample proves the RULE is not
    // vacuous, never that any particular name inside it is live.
    const rule = FORBIDDEN.find((r) => r.id === "dav-concurrent-request")!;
    expect(
      DAV_FAN_OUT_LIBRARY.length,
      "the request primitive and the tsdav helpers, plus phase 5's three writes and phase 14's three — makeCalendar, davRequest and deleteObject, the collection create, the hand-assembled property update and the collection removal the SPIKE-04 probe needs — and phase 16's one, createVCard, the CardDAV object create the contact write ends in. calendarQuery, which phase 14's to-do probe also calls, is NOT among them: it has been on this list since the event listing and must appear exactly once. CONW-02 adds the second phase-16 primitive, updateVCard, the CardDAV overwrite the conditional contact write ends in — the sharper of the two, because an overwrite aimed at the wrong origin does not merely leak the credential, it replaces whatever it addressed",
    ).toBe(20);
    for (const entryPoint of DAV_FAN_OUT_LIBRARY) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(
        fresh.test(fanOutOver(entryPoint)),
        `${entryPoint} is not named in the alternation`,
      ).toBe(true);
    }
  });

  it("refuses a name the alternation does not carry, so the two loops above have teeth", () => {
    // Guards the guards. Both loops substitute one name into a fixed template,
    // so if any OTHER token in that template were itself on the alternation,
    // every iteration would match for the wrong reason and both loops would
    // pass with the alternation gutted down to that one token. The template
    // used to spell the transport `davFetch`, which is exactly that token —
    // this control is what stops it coming back.
    const rule = FORBIDDEN.find((r) => r.id === "dav-concurrent-request")!;
    const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
    expect(
      fresh.test(fanOutOver("notADavEntryPoint")),
      "the fan-out template matches regardless of the name substituted into it — the per-name loops prove nothing",
    ).toBe(false);
  });

  it("keeps every per-name assertion CAPABLE of failing, with one recorded exception", () => {
    // The other way a per-name loop dies, and the one 05-13 found the hard way.
    // The alternation carries no leading word boundary, so a name that CONTAINS
    // another entry matches through that other entry — and its own loop
    // iteration passes whether or not the name is in the pattern at all.
    // `getEventWithEtag` is exactly that: `getEvent` precedes it and is a prefix
    // of it, so removing `getEventWithEtag` from the pattern breaks nothing in
    // the loop above and only the set-equality holds it there.
    //
    // Recorded as an EXACT LIST rather than tolerated, so a name added later
    // with the same defect fails here and has to be argued for. The three
    // `Preview` names WR-04 added are the case this was written against:
    // `buildPreview` is not a prefix of `buildCreatePreview` or
    // `buildDeletePreview`, so all three loops can genuinely fail — and this
    // proves that rather than asserting it in a comment.
    //
    // The repair for the exception is a trailing word boundary on the group,
    // which would make the rule match strictly LESS than it does today.
    // Narrowing a safety rule to tidy an assertion is what the Conventions
    // forbid outright, so the exception stays and is named here instead.
    const rule = FORBIDDEN.find((r) => r.id === "dav-concurrent-request")!;
    const names = alternationNamesOf(rule.pattern);
    expect(names.length, "the alternation extraction came back empty").toBeGreaterThan(
      10,
    );

    const covered = names.filter((name) =>
      names.some((other) => other !== name && name.includes(other)),
    );
    // `getContactWithEtag` (CONW-02) is the second, and it is the SAME defect on
    // the other tree: `getContact` precedes it in the alternation and is a prefix
    // of it, so it matched before it was written down. It is argued for here
    // rather than tolerated silently, which is what this exact list is for. The
    // alternative was to name it something `getContact` is not a prefix of, and
    // renaming a service export to satisfy a test's assertion mechanics is worse
    // than recording the mechanics — the name it has is the name `getEventWithEtag`
    // set on the tree this one is a twin of.
    expect(
      covered,
      "a name in the alternation is matched through another entry, so its per-name loop cannot fail",
    ).toEqual(["getEventWithEtag", "getContactWithEtag"]);
  });

  it("asserts every name in the shipped alternation, with nothing left over", () => {
    // The other direction, and the one neither loop above can supply. A loop
    // catches a name REMOVED from the pattern; only this catches a name ADDED
    // to it without an assertion — which is how the write half came to be
    // missing in the first place, one layer up.
    //
    // The union is hand-written; only the comparand is read from the shipped
    // rule. Deriving both sides from the pattern would make this agree with
    // itself by construction.
    const rule = FORBIDDEN.find((r) => r.id === "dav-concurrent-request")!;
    const asserted = [...DAV_FAN_OUT_SERVICE, ...DAV_FAN_OUT_LIBRARY].sort();
    expect(new Set(asserted).size, "a name is listed twice").toBe(asserted.length);
    expect(alternationNamesOf(rule.pattern).sort()).toEqual(asserted);
  });

  it("does not fire on a single service entry point call with no combinator", () => {
    // The permitted form, and the one every DAV tool in src/mcp/tools/ writes.
    // Widening the scope to src/ put those files inside this rule's reach for
    // the first time, so the false-positive direction has to be asserted there
    // too — a rule that could not tell an awaited call from a fan-out would be
    // switched off within a week.
    //
    // The write entry points are here for a second reason on top of that one.
    // Widening the alternation could be "fixed" by a pattern that matches
    // everything, and every positive assertion above would stay green while the
    // rule stopped discriminating. These are the exact lines src/mcp/tools/ and
    // src/dav/calendar.ts write on the permitted path — including the TWO-request
    // serial commit that plans 05-10 through 05-12 deliberately pay, because a
    // patch needs the whole resource and rebuilding drops every component it did
    // not rebuild. Multiple awaited requests are not what this rule bans.
    for (const permitted of [
      "const event = await getEvent(env, davFetch, params.eventId);",
      "return searchContacts(env, davFetch, { term, pageSize });",
      "const page = await listEvents(env, davFetch, options);",
      "const created = await createEvent(env, davFetch, input);",
      "const current = await getEventWithEtag(env, davFetch, ref);",
      "await updateEvent(env, davFetch, ref, body, current.etag);",
      "await deleteEvent(env, davFetch, ref, current.etag);",
    ]) {
      for (const rule of FORBIDDEN) {
        const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
        expect(fresh.test(permitted), `rule ${rule.id} false-positived`).toBe(false);
      }
    }
  });

  it("does not fire on a single DAV request with no combinator around it", () => {
    // The permitted form, and the one every DAV tool in this phase writes. A
    // rule that could not tell this from a fan-out would ban the transport it
    // exists to protect. The three write helpers are here for the same reason
    // their service callers are in the loop above: an awaited write is what
    // src/dav/calendar.ts does on every legitimate commit.
    for (const permitted of [
      "const books = await fetchAddressBooks({ account, headers: {}, fetch: davFetch });",
      "await createCalendarObject({ calendar, filename, iCalString, fetch: davFetch });",
      "await updateCalendarObject({ calendarObject, headers, fetch: davFetch });",
      "await deleteCalendarObject({ calendarObject, headers, fetch: davFetch });",
    ]) {
      for (const rule of FORBIDDEN) {
        const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
        expect(fresh.test(permitted), `rule ${rule.id} false-positived`).toBe(false);
      }
    }
  });

  // ------------------------------------------------ credential names in a log
  // Phase 8, CRED-05 (D-08). The rule-level guard above sees RULES, never the
  // names inside one: the rule's single sample names one binding, so a name
  // dropped from the alternation would leave every assertion above green. These
  // blocks are the per-name layer, copied from the DAV fan-out blocks.

  /** Every name the secret-in-log rule must carry. Hand-written on purpose, and
   *  never derived from the shipped pattern: a list read off the rule would
   *  agree with the rule by construction.
   *
   *  The first three are the Worker's secret bindings. The last two are the
   *  field names the grant's props use for the same two values. */
  const SECRET_LOG_NAMES = [
    "APPLE_APP_PASSWORD",
    "APPLE_ID",
    "AUTH_SECRET",
    "appPassword",
    "appleId",
  ];

  /** A logging call that reads one named field, with the name substituted in.
   *
   *  The object is deliberately spelled `holder`. It is NOT the environment
   *  object and it carries no name from the list, for the reason `fanOutOver`
   *  gives: a template that already holds a listed name matches on every pass
   *  no matter what is substituted, and the loop below would prove nothing. */
  const logCallNaming = (name: string) => `console.log("sending", holder.${name});`;

  it("names every credential field a log line could pass, binding and grant alike", () => {
    // One line per name. A sample proves the RULE is not vacuous, never that any
    // particular name inside it is live.
    const rule = FORBIDDEN.find((r) => r.id === "secret-binding-in-log-call")!;
    expect(SECRET_LOG_NAMES.length, "three bindings and the grant's two fields").toBe(5);
    for (const name of SECRET_LOG_NAMES) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(
        fresh.test(logCallNaming(name)),
        `${name} is not named in the alternation`,
      ).toBe(true);
    }
  });

  it("refuses a credential name the alternation does not carry, so the loop above has teeth", () => {
    // Guards the guard. If the template matched on its own, the loop above
    // would pass with the alternation gutted. The near-miss is here for a
    // second reason: the names match as whole identifiers with exact letter
    // case, so a longer identifier that merely STARTS with a listed name is
    // not seen. That is a known limit of the rule, and this pins it rather
    // than leaving it to be discovered.
    const rule = FORBIDDEN.find((r) => r.id === "secret-binding-in-log-call")!;
    for (const notListed of ["notASecretName", "appleIdentity"]) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(
        fresh.test(logCallNaming(notListed)),
        `the template matched for ${notListed}, which is not on the list — the per-name loop proves nothing`,
      ).toBe(false);
    }
  });

  it("asserts every name in the shipped secret alternation, with nothing left over", () => {
    // The other direction. The loop catches a name REMOVED from the pattern;
    // only this catches a name ADDED to it without a sample line. The list is
    // hand-written and only the comparand is read from the shipped rule.
    // `alternationNamesOf` throws when it finds no group, so an empty or garbled
    // alternation cannot pass here.
    const rule = FORBIDDEN.find((r) => r.id === "secret-binding-in-log-call")!;
    const asserted = [...SECRET_LOG_NAMES].sort();
    expect(new Set(asserted).size, "a name is listed twice").toBe(asserted.length);
    expect(alternationNamesOf(rule.pattern).sort()).toEqual(asserted);
  });

  // ---------------------------------------------- the grant's props in a log
  // Phase 8, CRED-05 (D-07). Same four-part shape as the block above: a
  // hand-written list, a per-name loop, a control, and a set-equality.

  /** Every name the props-in-log rule must carry. Hand-written, never derived.
   *
   *  The first four are D-07's. The fifth is the one password reader, added
   *  under the regex discretion. To drop it, delete it here and in the shipped
   *  alternation, and nothing else changes. */
  const PROPS_LOG_NAMES = [
    "props",
    "principal",
    "authInfo",
    "getMcpAuthContext",
    "passwordOf",
  ];

  /** A logging call that passes one named value, with the name substituted in.
   *
   *  The template carries no name from the list and does not mention the
   *  environment object, for the reason `fanOutOver` gives. The logger is
   *  spelled the second way the pattern allows, so both spellings are exercised
   *  across this file rather than one. */
  const propsLogCallNaming = (name: string) =>
    `logger.info("handler reached", requestId, ${name});`;

  it("names every handle on the grant's credentials a log line could pass", () => {
    const rule = FORBIDDEN.find((r) => r.id === "props-object-in-log-call")!;
    expect(PROPS_LOG_NAMES.length, "D-07's four names and the password reader").toBe(5);
    for (const name of PROPS_LOG_NAMES) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(
        fresh.test(propsLogCallNaming(name)),
        `${name} is not named in the alternation`,
      ).toBe(true);
    }
  });

  it("refuses a props name the alternation does not carry, so the loop above has teeth", () => {
    // Guards the guard, and pins the rule's known limit at the same time. The
    // two near-misses are the realistic ones: a variable that merely ENDS with
    // a listed name in another letter case, and a plural. Neither is seen,
    // because the names match as whole identifiers with exact case. The rule's
    // own comment says so; this proves it rather than asserting it.
    const rule = FORBIDDEN.find((r) => r.id === "props-object-in-log-call")!;
    for (const notListed of ["notOnTheList", "grantProps", "principals"]) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(
        fresh.test(propsLogCallNaming(notListed)),
        `the template matched for ${notListed}, which is not on the list — the per-name loop proves nothing`,
      ).toBe(false);
    }
  });

  it("asserts every name in the shipped props alternation, with nothing left over", () => {
    // Hand-written on one side, read from the shipped rule on the other.
    // `alternationNamesOf` reads the LAST non-capturing group, which for this
    // pattern is the name list. A later edit that adds a group after the names
    // makes it read the wrong group, and this goes red rather than quiet.
    const rule = FORBIDDEN.find((r) => r.id === "props-object-in-log-call")!;
    const asserted = [...PROPS_LOG_NAMES].sort();
    expect(new Set(asserted).size, "a name is listed twice").toBe(asserted.length);
    expect(alternationNamesOf(rule.pattern).sort()).toEqual(asserted);
  });

  it("sees the props behind an inner call's closing parenthesis", () => {
    // Why this rule's span is bounded by the statement and not by the next
    // closing parenthesis. The first argument here is itself a call, and its
    // `)` would end a paren-bounded span before the props were reached. The
    // second assertion shows that with a paren-bounded copy of the same rule,
    // so the claim in the rule's comment is measured rather than stated.
    const line = "console.log(describe(requestId), ctx.props);";
    const rule = FORBIDDEN.find((r) => r.id === "props-object-in-log-call")!;
    const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
    expect(fresh.test(line)).toBe(true);

    const parenBounded = /\b(?:console|logger)\.[a-z]+\s*\([^)]*\bprops\b/;
    expect(
      parenBounded.test(line),
      "a paren-bounded span was expected to miss this line; if it does not, the line no longer discriminates",
    ).toBe(false);
  });

  it("does not reach past the end of the statement for a props name", () => {
    // The other side of the statement bound. A log call that passes nothing
    // sensitive, followed by an ordinary statement that reads the props, is two
    // statements and not a leak. Both orders are here.
    const rule = FORBIDDEN.find((r) => r.id === "props-object-in-log-call")!;
    for (const permitted of [
      'console.log("handler reached"); const grant = ctx.props;',
      'const grant = ctx.props; console.log("handler reached");',
    ]) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(permitted), `fired across a semicolon: ${permitted}`).toBe(false);
    }
  });

  it("fires on a listed name that is only a word in the message, and that is a recorded choice", () => {
    // Code review WR-02. Every line here is INNOCENT: none passes a credential.
    // The rule fires on all of them anyway, because it reads text and not
    // syntax. That over-match is kept on purpose, and this test is what makes
    // it a known limit rather than a surprise. One of the names is everyday
    // DAV vocabulary, so the first row is the one a real author will meet.
    //
    // If this goes red, someone narrowed the rule. The fix for an innocent hit
    // is to reword the message or add the semicolon, never to make the rule
    // see less. The rule's own comment and its reason text both say so.
    const rule = FORBIDDEN.find((r) => r.id === "props-object-in-log-call")!;
    const innocentButRefused: ReadonlyArray<readonly [string, string]> = [
      ["a DAV word inside a string", 'console.log("principal-URL discovery failed");'],
      ["a listed name as a plain word in a string", 'console.log("checking the props rule");'],
      ["a listed name inside a trailing comment", 'console.log("ok", requestId) // props are not passed'],
      [
        "a listed name in the next statement, with no semicolon between",
        'console.log("ok")\nconst principal = await build()',
      ],
    ];
    expect(innocentButRefused.length).toBe(4);
    for (const [shape, line] of innocentButRefused) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(line), `the rule no longer fires on ${shape}: it was narrowed`).toBe(true);
    }

    // Why strings are not skipped. This one IS a leak, and it sits inside a
    // string: a template literal that interpolates the real object. A rule
    // that ignored string contents would miss it.
    const leakInsideAString = "console.log(`grant: ${JSON.stringify(ctx.props)}`);";
    const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
    expect(fresh.test(leakInsideAString)).toBe(true);

    // The hook prints the reason text, so it has to tell the author what to do.
    expect(rule.why).toContain("reword the message");
    expect(rule.why).toContain("Do not loosen this rule");
  });

  it("does not fire a name rule on a logging call that names nothing, and the blanket rule still does", () => {
    // Both halves, because either alone misleads. A logging call with an empty
    // argument list names nothing, so neither name rule can see it — an empty
    // match is not a match. Under src/ it is still refused, by the blanket
    // rule, which is the rule that does not depend on names at all.
    const empty = "console.log();";
    for (const id of ["secret-binding-in-log-call", "props-object-in-log-call"]) {
      const rule = FORBIDDEN.find((r) => r.id === id)!;
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(empty), `${id} fired on an empty argument list`).toBe(false);
    }
    const blanket = FORBIDDEN.find((r) => r.id === "logging-anywhere-under-src")!;
    expect(
      matchRule(blanket, FORBIDDEN.indexOf(blanket), "src/mcp/api-handler.ts", empty).length,
      "the blanket logging rule did not fire on an empty logging call under src/",
    ).toBeGreaterThan(0);
  });

  // ------------------------------- any logging method, in any letter case
  // Phase 9 (D-02, D-24). Until this phase the three name rules matched the
  // method as lower-case letters only, and the two blanket rules listed six
  // method names. So a timed-log or collapsed-group call that passed the
  // grant's props fired NO rule, under src/ included. All five now match any
  // identifier as the method. Same four-part shape as the blocks above: a
  // hand-written list, a per-item loop, a control, and a set-equality.
  //
  // `violatingSamples` holds ONE sample per rule id and is set-equal to the
  // rule ids, so a mixed-case line cannot be a new key there. These rows are
  // where the widening is proven instead.

  /** Real console methods with a capital letter in them. Hand-written. Every
   *  one is a line a contributor would really type while timing or grouping
   *  debug output, and every one was invisible to all five rules before. */
  const MIXED_CASE_LOG_METHODS = [
    "timeLog",
    "groupCollapsed",
    "countReset",
    "timeEnd",
    "timeStamp",
    "groupEnd",
  ];

  /** Real console methods that are all lower-case but were on neither blanket
   *  rule's six-name list. The name rules already saw these; the two blanket
   *  rules did not, so under src/ a table or dir call was free to log. */
  const UNLISTED_LOG_METHODS = ["table", "dir", "dirxml", "assert", "group", "count"];

  /** The five rules whose method part was widened. Hand-written, and compared
   *  below with what the shipped list actually holds. */
  const WIDENED_LOG_RULE_IDS = [
    "secret-binding-in-log-call",
    "logging-on-the-credential-path",
    "logging-anywhere-under-src",
    "env-object-in-log-call",
    "props-object-in-log-call",
  ];

  /** Each widened rule's pattern AS IT WAS at the phase base, typed out. This
   *  is the control: a row only proves the widening if the old text misses the
   *  same line. Never derive these from the shipped rules. */
  const OLD_LOG_PATTERNS: Record<string, RegExp> = {
    "secret-binding-in-log-call":
      /\b(?:console|logger)\.[a-z]+\([^)]*\b(?:APPLE_APP_PASSWORD|APPLE_ID|AUTH_SECRET|appPassword|appleId)\b/g,
    "logging-on-the-credential-path":
      /\b(?:console|logger)\.(?:log|info|warn|error|debug|trace)\s*\(/g,
    "logging-anywhere-under-src":
      /\b(?:console|logger)\.(?:log|info|warn|error|debug|trace)\s*\(/g,
    "env-object-in-log-call": /\b(?:console|logger)\.[a-z]+\([^)]*\benv\b/g,
    "props-object-in-log-call":
      /\b(?:console|logger)\.[a-z]+\s*\([^;]{0,400}?\b(?:props|principal|authInfo|getMcpAuthContext|passwordOf)\b/g,
  };

  /** A path inside each rule's reach. The two scoped rules only fire under
   *  their prefix, so they are driven through the real scope mechanism. The
   *  three unscoped ones are given a test path, to show they hold there too. */
  const LOG_RULE_PROBE_PATHS: Record<string, string> = {
    "secret-binding-in-log-call": "test/probe.test.ts",
    "logging-on-the-credential-path": "src/mail/probe.ts",
    "logging-anywhere-under-src": "src/mcp/probe.ts",
    "env-object-in-log-call": "test/probe.test.ts",
    "props-object-in-log-call": "test/probe.test.ts",
  };

  /** The logging line each rule needs, with the method substituted in.
   *
   *  Each line carries ONLY what its own rule looks for, so a row cannot pass
   *  because a neighbouring rule's trigger happens to be on the same line. */
  const logLineWithAccess = (ruleId: string, access: string): string => {
    switch (ruleId) {
      case "secret-binding-in-log-call":
        return `${access}("sending", holder.APPLE_APP_PASSWORD);`;
      case "env-object-in-log-call":
        return `${access}("diagnose", env);`;
      case "props-object-in-log-call":
        return `${access}("grant reached the handler", ctx.props);`;
      case "logging-on-the-credential-path":
      case "logging-anywhere-under-src":
        return `${access}("handler reached");`;
      default:
        throw new Error(`no logging line is defined for ${ruleId}`);
    }
  };

  const logLineFor = (ruleId: string, method: string): string =>
    logLineWithAccess(ruleId, `console.${method}`);

  /** The member-access spellings the dot-only pattern could not see (code
   *  review WR-02). The first is the ACCIDENT the widening is aimed at: the
   *  formatter breaks a long call after the object name, and a debug line
   *  carrying a wide object is exactly the call that wraps. The second is the
   *  optional-chaining member access, with the question mark BEFORE the dot —
   *  a different shape from the optional-CALL form pinned as an evasion below,
   *  which has it after the method name and still escapes. */
  const WIDENED_MEMBER_ACCESS: ReadonlyArray<readonly [string, string]> = [
    ["a line break before the dot, as the formatter writes it", "console\n  .log"],
    ["the optional-chaining member access", "console?.log"],
    ["a line break and the optional-chaining mark together", "console\n  ?.log"],
    ["a space on each side of the dot", "console . log"],
  ];

  const hitsOf = (ruleId: string, path: string, line: string): number => {
    const rule = FORBIDDEN.find((r) => r.id === ruleId)!;
    return matchRule(rule, FORBIDDEN.indexOf(rule), path, line).length;
  };

  it("fires every widened logging rule on a mixed-case console method", () => {
    // The gap this phase closes first. Before it, every line here fired no
    // rule at all. If this goes red, a method part was narrowed back.
    expect(MIXED_CASE_LOG_METHODS.length).toBeGreaterThanOrEqual(6);
    for (const method of MIXED_CASE_LOG_METHODS) {
      expect(method, `${method} holds no capital, so it is not a mixed-case row`).toMatch(/[A-Z]/);
      for (const id of WIDENED_LOG_RULE_IDS) {
        expect(
          hitsOf(id, LOG_RULE_PROBE_PATHS[id], logLineFor(id, method)),
          `${id} did not fire on the ${method} method`,
        ).toBeGreaterThan(0);
      }
    }
  });

  it("misses every mixed-case line with the old pattern text, so the rows above have teeth", () => {
    // Guards the guard. If the old text matched these lines too, the rows
    // above would pass with the widening reverted and would prove nothing.
    for (const method of MIXED_CASE_LOG_METHODS) {
      for (const id of WIDENED_LOG_RULE_IDS) {
        const old = OLD_LOG_PATTERNS[id];
        const fresh = new RegExp(old.source, old.flags);
        expect(
          fresh.test(logLineFor(id, method)),
          `the old ${id} pattern already saw the ${method} method: the line no longer discriminates`,
        ).toBe(false);
      }
    }
  });

  it("fires both blanket rules on a lower-case method the old six-name list left out", () => {
    // The blanket rules' own gap, and a different one from letter case: the
    // method is all lower-case and simply was not one of the six. The old text
    // misses the same line, which is what makes the row mean something.
    expect(UNLISTED_LOG_METHODS.length).toBeGreaterThanOrEqual(6);
    for (const method of UNLISTED_LOG_METHODS) {
      expect(method, `${method} is not all lower-case`).toMatch(/^[a-z]+$/);
      for (const id of ["logging-on-the-credential-path", "logging-anywhere-under-src"]) {
        const line = logLineFor(id, method);
        expect(
          hitsOf(id, LOG_RULE_PROBE_PATHS[id], line),
          `${id} did not fire on the ${method} method`,
        ).toBeGreaterThan(0);

        const old = OLD_LOG_PATTERNS[id];
        const fresh = new RegExp(old.source, old.flags);
        expect(
          fresh.test(line),
          `the old six-name list already held ${method}: the line no longer discriminates`,
        ).toBe(false);
      }
    }
  });

  it("fires every widened logging rule on a member access the dot-only text missed", () => {
    // Code review WR-02. The dot had to be bare, so a wrapped call and an
    // optional-chaining member access fired nothing. The old text misses the
    // same lines, which is what makes these rows mean something.
    expect(WIDENED_MEMBER_ACCESS.length).toBe(4);
    for (const [shape, access] of WIDENED_MEMBER_ACCESS) {
      for (const id of WIDENED_LOG_RULE_IDS) {
        const line = logLineWithAccess(id, access);
        expect(
          hitsOf(id, LOG_RULE_PROBE_PATHS[id], line),
          `${id} did not fire on ${shape}`,
        ).toBeGreaterThan(0);

        const old = OLD_LOG_PATTERNS[id];
        expect(
          new RegExp(old.source, old.flags).test(line),
          `the old ${id} pattern already saw ${shape}: the line no longer discriminates`,
        ).toBe(false);
      }
    }
  });

  it("keeps the widened member access inside the two scoped rules' scope", () => {
    // Widening the member access must not widen the reach, exactly as widening
    // the method part must not.
    for (const [shape, access] of WIDENED_MEMBER_ACCESS) {
      for (const id of ["logging-on-the-credential-path", "logging-anywhere-under-src"]) {
        expect(
          hitsOf(id, "test/probe.test.ts", logLineWithAccess(id, access)),
          `${id} fired on a test file through ${shape}`,
        ).toBe(0);
      }
      expect(
        hitsOf(
          "logging-on-the-credential-path",
          "src/mcp/probe.ts",
          logLineWithAccess("logging-on-the-credential-path", access),
        ),
        `the src/mail/ rule fired outside src/mail/ through ${shape}`,
      ).toBe(0);
    }
  });

  it("types out old patterns that really were the rules, and the new ones still see the old samples", () => {
    // Two controls in one. A mistyped entry in OLD_LOG_PATTERNS would miss
    // every line, and the "old text misses it" tests above would pass for the
    // wrong reason. So each old pattern must FIRE on its rule's standing
    // sample. And the widened rule must fire on it too: only refuses more.
    for (const id of WIDENED_LOG_RULE_IDS) {
      const sample = violatingSamples[id];
      const old = OLD_LOG_PATTERNS[id];
      expect(
        new RegExp(old.source, old.flags).test(sample),
        `the typed-out old pattern for ${id} misses the rule's own sample, so it is not the old rule`,
      ).toBe(true);
      const rule = FORBIDDEN.find((r) => r.id === id)!;
      expect(
        new RegExp(rule.pattern.source, rule.pattern.flags).test(sample),
        `${id} lost its standing sample when it was widened`,
      ).toBe(true);
    }
  });

  it("keeps the two scoped logging rules inside their scope", () => {
    // Widening the method must not widen the reach. The same mixed-case line
    // in a test file fires neither scoped rule, and the credential-path rule
    // stays out of the rest of src/.
    for (const method of [...MIXED_CASE_LOG_METHODS, ...UNLISTED_LOG_METHODS]) {
      for (const id of ["logging-on-the-credential-path", "logging-anywhere-under-src"]) {
        expect(
          hitsOf(id, "test/probe.test.ts", logLineFor(id, method)),
          `${id} fired on a test file through the ${method} method`,
        ).toBe(0);
      }
      expect(
        hitsOf(
          "logging-on-the-credential-path",
          "src/mcp/probe.ts",
          logLineFor("logging-on-the-credential-path", method),
        ),
        "the src/mail/ rule fired outside src/mail/",
      ).toBe(0);
    }
  });

  it("covers every rule that opens with the console-or-logger group, with nothing left over", () => {
    // The other direction. A sixth logging rule added later without rows here
    // would be unproven against letter case and would look exactly like a
    // proven one. The list is hand-written; only the comparand is read from
    // the shipped rules.
    const opensWithLoggerGroup = FORBIDDEN.filter((rule) =>
      rule.pattern.source.startsWith("\\b(?:console|logger)"),
    ).map((rule) => rule.id);
    const asserted = [...WIDENED_LOG_RULE_IDS].sort();
    expect(new Set(asserted).size, "a rule id is listed twice").toBe(asserted.length);
    expect(opensWithLoggerGroup.sort()).toEqual(asserted);
    expect(Object.keys(OLD_LOG_PATTERNS).sort()).toEqual(asserted);
    expect(Object.keys(LOG_RULE_PROBE_PATHS).sort()).toEqual(asserted);
  });

  it("still cannot see the five evasions the rule comments list, and says so", () => {
    // Pins the known limits so nobody believes they are covered. Every line
    // here passes the grant's props to a log and fires NO widened rule, under
    // src/ included. They are evasions rather than accidents, and the rules
    // are aimed at the accident. If one of these starts firing, a rule got
    // better: move the row out of this list and update the rule's comment.
    const evasions: ReadonlyArray<readonly [string, string]> = [
      ["a computed member on the console object", 'console["timeLog"]("grant", ctx.props);'],
      ["a method pulled out by destructuring", 'const { timeLog } = console;\ntimeLog("grant", ctx.props);'],
      ["an alias of the console object", 'const out = console;\nout.timeLog("grant", ctx.props);'],
      ["the optional-call form", 'console.timeLog?.("grant", ctx.props);'],
      ["a logger under another name", 'pino.info("grant", ctx.props);'],
    ];
    expect(evasions.length).toBe(5);
    for (const [shape, line] of evasions) {
      for (const id of WIDENED_LOG_RULE_IDS) {
        expect(
          hitsOf(id, LOG_RULE_PROBE_PATHS[id], line),
          `${id} now sees ${shape}; move this row and update the rule's comment`,
        ).toBe(0);
      }
    }
  });

  it("runs each widened logging pattern in linear time on a long method name with no call", () => {
    // The new method part is a run of word characters followed by an optional
    // white-space run and a parenthesis. With no parenthesis anywhere, the run
    // has to be given back one character at a time. That is linear, and this
    // holds it there: the sizes climb, so a regression fails early with a
    // message rather than hanging on the longest line.
    const BOUND_MS = 500;
    for (const id of WIDENED_LOG_RULE_IDS) {
      const rule = FORBIDDEN.find((r) => r.id === id)!;
      for (const length of [1_000, 10_000, 100_000, 1_000_000]) {
        const line = `console.${"aB_$9".repeat(length / 5)} ;`;
        const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
        const started = performance.now();
        const hit = fresh.test(line);
        const ms = performance.now() - started;
        expect(hit, `${id} fired on a member read that is not a call`).toBe(false);
        expect(ms, `${id} took ${ms.toFixed(0)} ms on ${length} characters`).toBeLessThan(BOUND_MS);
      }
    }
  });

  // -------------------------------------------- writes onto the env object
  // Phase 8, CRED-05 (D-09). This rule has no name list: the last non-capturing
  // group in its source is the dotted prefix inside the merge arm, so
  // `alternationNamesOf` would read the wrong group. One line per FORM instead.

  /** Every form of write the rule must refuse, one line each. */
  const ENV_WRITE_FORMS: ReadonlyArray<readonly [string, string]> = [
    ["member assignment", "env.APPLE_ID = userB.appleId;"],
    ["index assignment", 'env["APPLE_ID"] = userB.appleId;'],
    ["compound addition", "env.RETRY_BUDGET += 1;"],
    ["compound nullish assignment", "env.APPLE_ID ??= userB.appleId;"],
    ["nested member", "env.DAV_CACHE.put = stubPut;"],
    ["member on this", "this.env.APPLE_ID = userB.appleId;"],
    ["member on the next line", "env\n  .APPLE_ID = userB.appleId;"],
    ["object merge onto it", "Object.assign(env, { APPLE_ID: userB.appleId });"],
    [
      "object merge onto a dotted path ending in it",
      "Object.assign(ctx.env, { APPLE_ID: userB.appleId });",
    ],
    // Code review WR-01. The forms the first version of the rule missed. The
    // cast is the important one: a plain write onto the object is a type error,
    // so the cast is the very next thing an author tries.
    ["member assignment through a type cast", "(env as Env).APPLE_ID = userB.appleId;"],
    [
      "member assignment through a chained type cast",
      "(env as unknown as Record<string, string>).APPLE_ID = userB.appleId;",
    ],
    ["member assignment after a non-null mark", "env!.APPLE_ID = userB.appleId;"],
    ["non-null mark between two links of the chain", "env.DAV_CACHE!.put = stubPut;"],
    ["postfix increment", "env.RETRY_BUDGET++;"],
    ["postfix decrement", "env.RETRY_BUDGET--;"],
    ["prefix increment", "++env.RETRY_BUDGET;"],
    ["prefix decrement", "--env.RETRY_BUDGET;"],
    ["prefix increment through a type cast", "++(env as Env).RETRY_BUDGET;"],
    ["prefix increment on a dotted path ending in it", "++this.env.RETRY_BUDGET;"],
    ["prefix increment on an index", '++env["RETRY_BUDGET"];'],
    ["computed key holding square brackets", "env[keys[0]] = userB.appleId;"],
    // The first version already saw this one. It is here so a later rewrite of
    // the index arm into a balanced-brackets-only form goes red.
    ["index key holding an unclosed bracket", 'env["a[b"] = userB.appleId;'],
    // Second code review, WR-01. The timing repair moved the white space in
    // front of the non-null mark into the mark's own group. These two hold the
    // white space on BOTH sides of the mark, so a repair that dropped either
    // side to get its speed would go red here.
    ["non-null mark with a space on each side", "env.DAV_CACHE ! .put = stubPut;"],
    ["non-null mark on its own line", "env.DAV_CACHE\n  !\n  .put = stubPut;"],
  ];

  /** Reads, comparisons, declarations and copies. None is a write onto the
   *  shared object, so NO rule on the list may fire on any of them.
   *
   *  THE BINDING NAMES HERE ARE INCIDENTAL, and several of them changed in
   *  Phase 13. These rows exist to prove the environment-WRITE rule stays off
   *  the read side of every form it sees on the write side, so what matters is
   *  the shape of each line and not which binding it happens to name. Four rows
   *  used to name an account binding, and once a read of one became a plain ban
   *  they stopped being permitted lines at all — so they name a live binding
   *  instead. Swapping the name keeps every claim these rows make; leaving it
   *  and loosening the ban to suit them would not, and exclusion is by path
   *  here as everywhere. The ban's own firing on a plain read is recorded as a
   *  deliberate choice in its own block further down. */
  const ENV_READS_AND_COPIES: ReadonlyArray<readonly [string, string]> = [
    ["strict equality", "if (env.MODE === expected) return;"],
    ["loose equality", "if (env.MODE == expected) return;"],
    ["inequality", "if (env.LIMIT !== expected) return;"],
    [
      "less-or-equal and greater-or-equal",
      "const inRange = env.LIMIT <= ceiling && env.LIMIT >= floor;",
    ],
    ["a declaration of a local with this name", "const env = makeEnv();"],
    ["a typed let declaration", "let env: Env = makeEnv();"],
    ["an arrow parameter", "const run = (env: Env) => handle(env);"],
    // A new object with fields overridden, which is the form the env-write rule
    // points people at instead of writing onto the shared object. It must leave
    // the permitted form alone, or it bans the fix it recommends. A fixture in
    // test/ built exactly this shape over the two account bindings until Phase 13
    // deleted them; the shape is what is being pinned, so the row outlived the
    // caller and keeps the old names to prove the OBJECT-LITERAL KEY form is
    // still not a read — a key is not a member access, which is why the account
    // -binding ban is silent here too.
    [
      "a spread copy with fields overridden",
      "return { ...(env as Env), APPLE_ID: user.appleId, APPLE_APP_PASSWORD: user.appPassword };",
    ],
    ["an assignment on a differently named object", "testEnv.APPLE_ID = userB.appleId;"],
    ["a ternary that reads it", "const id = env.MODE ? env.MODE : fallback;"],
    [
      "an object merge INTO an empty object",
      "const copy = Object.assign({}, env, { APPLE_ID: userB.appleId });",
    ],
    // Code review WR-01. The widened rule must stay off the READ side of every
    // form it newly sees on the write side.
    ["a read through a type cast", "const appleId = (env as Env).APPLE_ID;"],
    ["a comparison through a type cast", "const inRange = (env as Env).LIMIT >= floor;"],
    ["a call through a type cast", "const out = (env as Env).handler(() => 1);"],
    ["a read after a non-null mark", "const secret = env!.CONFIRM_SECRET;"],
    ["a read through a computed key", "const value = env[keys[0]];"],
    // The non-null mark and the loose inequality share a character. A mark
    // allowed right before the operator would turn this comparison into a hit.
    ["loose inequality", "if (env.MODE != expected) return;"],
    ["an increment of something else, then a read", "const sum = i++ + env.LIMIT;"],
    ["the same with no spaces", "const sum = i+++env.LIMIT;"],
    ["a subtraction of a negative", "const less = env.LIMIT - -1;"],
    // The prefix arm opens on two dashes, and so does a command-line flag.
    ["a command-line flag with this name", 'const args = ["deploy", "--env", "staging"];'],
    ["the same flag with a value attached", 'const args = ["deploy", "--env=staging"];'],
    ["the same flag at the end of a sentence", "// pass --env. Then deploy."],
    ["a prefix decrement of a local with this name", "const n = --env;"],
  ];

  it("refuses every form of write onto the env object", () => {
    const rule = FORBIDDEN.find((r) => r.id === "env-assignment")!;
    expect(
      ENV_WRITE_FORMS.length,
      "9 forms from D-09 and their variants, 13 from code review WR-01, 2 from the second review",
    ).toBe(24);
    for (const [form, line] of ENV_WRITE_FORMS) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(line), `the ${form} form was not seen`).toBe(true);
    }
  });

  /** Every compound operator the rule's operator group carries. Hand-written,
   *  never read from the pattern.
   *
   *  Code review WR-04. The first version of this file held a row for two of
   *  these and none for the rest, so deleting any other arm of the group left
   *  the whole suite green. An arm with no sample is invisible to every other
   *  assertion here, the rule-level set-equality included. One row per arm.
   *
   *  The two shift operators that share an arm in the pattern each get a row,
   *  because that arm has an optional third character and either half of it can
   *  be deleted on its own. */
  const ENV_COMPOUND_OPERATORS = [
    "**",
    "<<",
    ">>",
    ">>>",
    "&&",
    "||",
    "??",
    "-",
    "+",
    "*",
    "/",
    "%",
    "&",
    "|",
    "^",
  ];

  /** A compound write onto the object, with the operator substituted in. */
  const compoundWriteWith = (operator: string) => `env.RETRY_BUDGET ${operator}= other;`;

  it("refuses a compound write onto the env object for every operator, one row per arm", () => {
    const rule = FORBIDDEN.find((r) => r.id === "env-assignment")!;
    expect(ENV_COMPOUND_OPERATORS.length, "every compound assignment operator").toBe(15);
    expect(new Set(ENV_COMPOUND_OPERATORS).size, "an operator is listed twice").toBe(
      ENV_COMPOUND_OPERATORS.length,
    );
    for (const operator of ENV_COMPOUND_OPERATORS) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(
        fresh.test(compoundWriteWith(operator)),
        `the ${operator}= arm is missing from the operator group`,
      ).toBe(true);
    }
  });

  it("does not fire the compound template on a comparison, so the loop above has teeth", () => {
    // Guards the guard. If the template matched whatever was substituted in,
    // the per-operator loop would prove nothing. These six are comparisons
    // spelled through the same template, and none is a write.
    const rule = FORBIDDEN.find((r) => r.id === "env-assignment")!;
    for (const comparison of ["=", "==", "!", "!=", "<", ">"]) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(
        fresh.test(compoundWriteWith(comparison)),
        `the template matched for ${comparison}=, which is a comparison`,
      ).toBe(false);
    }
  });

  it("runs in linear time on a long spaced chain that does not end in a write", () => {
    // Second code review, WR-01. The first widened version of this rule had an
    // optional mark with a white-space run on each side, inside the chain loop.
    // With no mark present, a space before a dot could be taken by either run,
    // so a chain that did NOT end in a write cost double for every link: about
    // 25 links took seconds and 2,000 never finished. A new line is white
    // space, so an ordinary multi-line chain has that shape. The rule has no
    // scope and runs in both gates, so one such line hung the hook silently.
    //
    // A pattern match cannot be interrupted, so a test timeout would not save
    // this test from a regression: it would hang, which is the very failure it
    // is here to report. So it CLIMBS. Each short chain must finish inside the
    // bound before the next, longer one is tried. With the doubling defect the
    // climb fails in about a second at two dozen links, with a message, and
    // the long chains are never reached.
    const rule = FORBIDDEN.find((r) => r.id === "env-assignment")!;
    const BOUND_MS = 500;
    const spaced = (links: number) => `env${" . a".repeat(links)} ;`;
    const multiLine = (links: number) => `env${"\n  .a".repeat(links)}\n;`;
    const marked = (links: number) => `env${" ! . a".repeat(links)} ;`;

    const timed = (text: string): { ms: number; hit: boolean } => {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      const started = performance.now();
      const hit = fresh.test(text);
      return { ms: performance.now() - started, hit };
    };

    for (const shape of [spaced, multiLine, marked]) {
      for (const links of [8, 12, 16, 20, 24, 28]) {
        const { ms, hit } = timed(shape(links));
        expect(hit, `fired on a ${links}-link chain with no write`).toBe(false);
        expect(
          ms,
          `${links} links took ${ms.toFixed(0)} ms: the cost is doubling per link, so the chain loop has two ways to match one space`,
        ).toBeLessThan(BOUND_MS);
      }
    }

    // Only now the long ones. Several thousand links, far past anything real.
    for (const [name, text] of [
      ["spaced", spaced(5000)],
      ["multi-line", multiLine(5000)],
      ["spaced with a mark on every link", marked(5000)],
    ] as const) {
      const { ms, hit } = timed(text);
      expect(hit, `fired on the long ${name} chain, which holds no write`).toBe(false);
      expect(ms, `the long ${name} chain took ${ms.toFixed(0)} ms`).toBeLessThan(BOUND_MS);
    }

    // The control. The same long chains DO fire once a write ends them, so
    // "did not match" above is the missing write and not a blind pattern.
    for (const text of [`env${" . a".repeat(5000)} = 1;`, `env${"\n  .a".repeat(5000)}\n  = 1;`]) {
      const { ms, hit } = timed(text);
      expect(hit, "a long chain that ends in a write was not seen").toBe(true);
      expect(ms).toBeLessThan(BOUND_MS);
    }
  });

  it("does not fire on a read, a comparison, a declaration or a copy of the env object", () => {
    // Every rule, not only the new one, in the style of the permitted-line
    // loops above: a false positive in ANY rule shows here. A rule that banned
    // the spread copy would ban the right way to be another user.
    expect(ENV_READS_AND_COPIES.length).toBeGreaterThan(0);
    for (const [shape, permitted] of ENV_READS_AND_COPIES) {
      for (const rule of FORBIDDEN) {
        const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
        expect(
          fresh.test(permitted),
          `rule ${rule.id} false-positived on ${shape}`,
        ).toBe(false);
      }
    }
  });

  it("fires on a write onto another environment table and on a comment, and that is a recorded choice", () => {
    // Code review WR-03. Every line here is INNOCENT: none writes onto the
    // Worker's environment object. The rule fires on all of them anyway,
    // because it is anchored on the word and reads text, not syntax. That
    // over-match is kept on purpose, and this test is what makes it a known
    // limit rather than a surprise.
    //
    // If this goes red, someone narrowed the rule. The fix for an innocent hit
    // is to set the variable from outside the script, pass a fresh copy, or
    // describe the form by role in the comment. Never make the rule see less.
    const rule = FORBIDDEN.find((r) => r.id === "env-assignment")!;
    const innocentButRefused: ReadonlyArray<readonly [string, string]> = [
      ["a write onto the Node process's table", 'process.env.NODE_ENV = "test";'],
      ["a write onto the build tool's table", 'import.meta.env.MODE = "x";'],
      ["a comment that spells the write out", "// before: env.APPLE_ID = userB.appleId"],
      ["a string that spells the write out", 'const hint = "do not write env.APPLE_ID = x";'],
    ];
    expect(innocentButRefused.length).toBe(4);
    for (const [shape, line] of innocentButRefused) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(line), `the rule no longer fires on ${shape}: it was narrowed`).toBe(true);
    }

    // The hook prints the reason text, so it has to tell the author what to do.
    expect(rule.why).toContain("describe the form by role");
    expect(rule.why).toContain("Do not loosen this rule");
  });

  it("fires on a double dash used as punctuation and on a dotted flag, and that is a recorded choice", () => {
    // Second code review, IN-05. Every line here is INNOCENT, and none of them
    // spells a write out. The prefix arm opens on two dashes, allows a space,
    // then wants the name and an accessor, so a dash used as punctuation right
    // in front of a plain read looks the same to it as a prefix decrement. The
    // over-match is kept on purpose, and this test is what makes it a known
    // limit rather than a surprise.
    //
    // If this goes red, someone narrowed the rule. The fix for an innocent hit
    // is a different dash, a word between the dash and the name, or the flag's
    // value passed as its own argument. Never make the rule see less.
    const rule = FORBIDDEN.find((r) => r.id === "env-assignment")!;
    const innocentButRefused: ReadonlyArray<readonly [string, string]> = [
      [
        "a double dash as punctuation before a read, in a comment",
        "// the binding is absent -- env.APPLE_ID reads as undefined",
      ],
      [
        "the same before the first of two reads",
        "// two cases -- env.MODE set, and env.MODE unset",
      ],
      [
        "the same inside a string",
        'const note = "unset binding -- env.APPLE_ID is undefined";',
      ],
      ["a flag with a dotted suffix", 'const args = ["deploy", "--env.staging"];'],
    ];
    expect(innocentButRefused.length).toBe(4);
    for (const [shape, line] of innocentButRefused) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(line), `the rule no longer fires on ${shape}: it was narrowed`).toBe(true);
    }

    // The advice the reason text gives really does clear the line. Each of
    // these is one of the rows above with that advice applied.
    for (const reworded of [
      "// the binding is absent, so env.APPLE_ID reads as undefined",
      "// the binding is absent -- then env.APPLE_ID reads as undefined",
      'const args = ["deploy", "--env", "staging"];',
    ]) {
      const fresh = new RegExp(rule.pattern.source, rule.pattern.flags);
      expect(fresh.test(reworded), `the advice did not clear: ${reworded}`).toBe(false);
    }

    // The hook prints the reason text, so it has to tell the author what to do.
    expect(rule.why).toContain("use a different dash");
    expect(rule.why).toContain("Do not loosen this rule");
  });

  it("holds both new rules in every scanned directory, driven through the scanner's own matcher", () => {
    // Not `rule.scope === undefined`: that would restate the scanner's prefix
    // logic here and pass even if `matchRule` grew a default scope. Driving the
    // real matcher over one path per scanned root is what proves "no scope"
    // rather than declaring it.
    for (const id of ["props-object-in-log-call", "env-assignment"]) {
      const rule = FORBIDDEN.find((r) => r.id === id)!;
      const index = FORBIDDEN.indexOf(rule);
      const sample = violatingSamples[id]!;
      for (const path of [
        "src/mcp/api-handler.ts",
        "scripts/probe.mjs",
        "test/some.test.ts",
      ]) {
        expect(
          matchRule(rule, index, path, sample).length,
          `${id} did not fire under ${path}`,
        ).toBeGreaterThan(0);
      }
    }
  });
});

describe("the scanned surface", () => {
  // `scan()` with no argument is the multi-root scan, and it is the exact call
  // the CLI entry point makes. Asserting on it is therefore asserting on the
  // commit gate rather than on a narrower cousin of it.

  it("runs the socket-ownership check once across all roots, not once per root", () => {
    // Each root on its own reports the choke-point missing, because only one of
    // them contains socket code. A per-root check would therefore fail the scan
    // the moment scripts/ and test/ were added to the surface.
    expect(scan("scripts").map((v) => v.pattern)).toContain("socket-choke-point-missing");
    expect(scan("test").map((v) => v.pattern)).toContain("socket-choke-point-missing");
    expect(scan().map((v) => v.pattern)).not.toContain("socket-choke-point-missing");
  });

  it("walks test/, proven by the violating samples in this very file", () => {
    // With the skip disabled this file's samples are findable, which is only
    // possible if test/ is inside the default surface at all. Behavioural
    // rather than an assertion about a root list, so it keeps holding for
    // whatever files later phases add to the directory.
    const files = scan(undefined, NO_EXCLUSIONS).map((v) => v.file);
    expect(files).toContain(THIS_TEST_PATH);
  });

  it("finds everything a single-root scan finds, for each root separately", () => {
    // The superset property, stated per-directory rather than per-file: no
    // matter what a later phase adds under src/, scripts/, or test/, anything a
    // scan of that one directory would catch is caught by the scan the hook
    // runs. The ownership check is excluded because it is deliberately a
    // whole-surface property, and is asserted above.
    const key = (v: { file: string; line: number; column: number; pattern: string }) =>
      `${v.file}:${v.line}:${v.column}:${v.pattern}`;
    const wholeSurface = scan(undefined, NO_EXCLUSIONS).map(key);
    for (const root of ["src", "scripts", "test"]) {
      for (const violation of scan(root, NO_EXCLUSIONS)) {
        // Every COUNT constraint is excluded here, not only the socket one, and
        // the carve-out is named by the exported list rather than by a string
        // prefix so a constraint added later cannot fall outside it silently. A
        // count is deliberately a whole-surface property: scanning one root in
        // isolation reports the owners living in the other roots as missing,
        // which is correct for that narrower question and wrong for this one.
        // Each direction of each count is asserted on its own below.
        if (OWNERSHIP_VIOLATION_IDS.includes(violation.pattern)) continue;
        expect(wholeSurface, `${root} contributed a violation the gate misses`).toContain(
          key(violation),
        );
      }
    }
  });
});

describe("the current tree", () => {
  it("is clean", () => {
    // Mapped through formatViolation so a failure reads as the reason the rule
    // exists, not as a dump of objects.
    expect(scan().map(formatViolation)).toEqual([]);
  });

  it("carries no nonexistent limits key, and hardcodes no deployed hostname", () => {
    // Wave 1 established that `wrangler deploy --dry-run` accepts the limits key
    // silently, so the tooling will never report that it does nothing. The
    // hostname half asserts src/ re-exports the generated value rather than
    // hardcoding a literal that nothing forces to match the wrangler route.
    expect(scanWranglerConfig().map(formatViolation)).toEqual([]);
  });

  it("fires hostname-hardcoded when src hardcodes a deployed hostname literal", () => {
    // A guard that can never fail is indistinguishable from one that was never
    // added. Point the check at a sample that hardcodes the literal and confirm
    // it rejects it.
    const violations = scanWranglerConfig(
      "wrangler.jsonc",
      "test/fixtures/hostname-hardcoded-sample.ts",
    );
    expect(violations.map((v) => v.pattern)).toEqual(["hostname-hardcoded"]);
  });
});

describe("determinism", () => {
  it("produces identical results on two runs over the same tree", () => {
    expect(scan()).toEqual(scan());
  });

  it("stays identical across repeated runs, so no rule carries state between files", () => {
    // A shared global regex carries `lastIndex` from one file to the next. If
    // the scanner reused one, a later pass would skip matches an earlier pass
    // found, and the lists would diverge.
    const first = scan("scripts");
    expect(scan("scripts")).toEqual(first);
    expect(scan("scripts")).toEqual(first);
  });
});

describe("self-exclusion", () => {
  it("names both self-referential files in EXCLUDED", () => {
    expect(EXCLUDED.has(SCANNER_PATH)).toBe(true);
    expect(EXCLUDED.has(THIS_TEST_PATH)).toBe(true);
  });

  it("actually skips the scanner when its own directory is the root", () => {
    const violations = scan("scripts");
    expect(violations.filter((v) => v.file === SCANNER_PATH)).toEqual([]);
  });

  it("actually skips this test file when its own directory is the root", () => {
    const violations = scan("test");
    expect(violations.filter((v) => v.file === THIS_TEST_PATH)).toEqual([]);
  });

  it("would flag this file without the skip, so the exclusion is load-bearing", () => {
    // The same scan over the same tree with exclusion disabled. Without this,
    // the assertion above would be proving only that this file happens to be
    // clean — a scanner that passes because it cannot see itself is worthless,
    // and so is a self-exclusion that is never exercised.
    const withSkip = scan("test").filter((v) => v.file === THIS_TEST_PATH);
    const withoutSkip = scan("test", NO_EXCLUSIONS).filter(
      (v) => v.file === THIS_TEST_PATH,
    );
    expect(withoutSkip.length).toBeGreaterThan(0);
    expect(withSkip).toEqual([]);
  });

  it("still skips both files under the multi-root scan the hook actually runs", () => {
    // The single-root cases above prove the skip works when the file's own
    // directory is the root. This proves it survives the widening — scripts/
    // and test/ are now inside the scanner's own search space, so the skip is
    // load-bearing on every commit rather than only in these two tests.
    const violations = scan();
    expect(violations.filter((v) => v.file === SCANNER_PATH)).toEqual([]);
    expect(violations.filter((v) => v.file === THIS_TEST_PATH)).toEqual([]);
  });

  it("would flag this file under the multi-root scan too, without the skip", () => {
    expect(
      scan(undefined, NO_EXCLUSIONS).filter((v) => v.file === THIS_TEST_PATH).length,
    ).toBeGreaterThan(0);
  });

  it("no longer relies on the scanner's pattern spellings failing to self-match", () => {
    // **That day has arrived, and this case now records it rather than
    // predicting it.** Until Phase 17 the scanner's own regex literals happened
    // not to match themselves: a word-boundary escape puts a word character
    // immediately before the banned identifier, and the quoted-string patterns
    // put a bracket where a quote would have to be. This case said in as many
    // words that the coincidence was a coincidence and that one reworded `why`
    // string would end it.
    //
    // What ended it is not a reworded string. It is STRUCTURAL and cannot be
    // undone without giving up a rule: the request-fan-out rule's alternation
    // lists the DAV library's collection-creation helper by name, delimited by
    // `|` on both sides — which is a word boundary — so the moment a rule banned
    // that name outright, the scanner file began matching its own pattern. The
    // alternation entry is load-bearing (it is what makes a future call site
    // visible to the containment gate's vocabulary) and the new rule is
    // load-bearing, so neither side can be given up to restore the coincidence.
    //
    // The assertion is therefore turned the other way up, which is STRONGER
    // than what it replaced: the path exclusion is no longer merely believed to
    // be load-bearing, it is shown to be. Without the skip this file is flagged;
    // with it, it is clean. That is exactly the shape of the sibling case above
    // for this test file, and it is the assertion a future reader needs — the
    // one that stops them concluding the skip is dead weight and deleting it.
    expect(EXCLUDED.has(SCANNER_PATH)).toBe(true);
    expect(
      scan("scripts", NO_EXCLUSIONS).filter((v) => v.file === SCANNER_PATH).length,
      "the scanner file no longer self-matches, so the path skip is guarding nothing. Work out which rule stopped firing before changing this expectation.",
    ).toBeGreaterThan(0);
    expect(scan("scripts").filter((v) => v.file === SCANNER_PATH)).toEqual([]);
  });
});

describe("the socket choke-point is a count constraint, not a pure negative", () => {
  // Referred to only through the imported SOCKET_IMPORT and SOCKET_OWNER
  // identifiers. The module specifier itself is never written into this file —
  // not in a fixture string, not in a title, not in a comment.
  const owner = { file: SOCKET_OWNER, line: 1, column: 1 };
  const elsewhere = { file: "src/mail/imap-session.ts", line: 4, column: 1 };

  it("passes when exactly one file reaches it and that file is SOCKET_OWNER", () => {
    expect(checkSocketOwnership([owner])).toEqual([]);
  });

  it("reports a violation when a second file reaches it", () => {
    const violations = checkSocketOwnership([owner, elsewhere]);
    expect(violations.map((v) => v.pattern)).toEqual(["socket-choke-point-duplicated"]);
    expect(violations[0]!.file).toBe(elsewhere.file);
  });

  it("reports a violation when no file reaches it", () => {
    // A silently-deleted choke-point guards nothing, which is exactly as bad as
    // a duplicated one and much easier to miss.
    const violations = checkSocketOwnership([]);
    expect(violations.map((v) => v.pattern)).toEqual(["socket-choke-point-missing"]);
  });

  it("is wired into scan(): a tree with no such file fails", () => {
    // scripts/ contains no file matching SOCKET_IMPORT, so scanning it exercises
    // the deleted direction against a real tree rather than a synthetic list.
    expect(scan("scripts").map((v) => v.pattern)).toContain("socket-choke-point-missing");
  });

  it("still matches the file the ban names", () => {
    // scan() over src/ is clean, which given the two directions above can only
    // be true if SOCKET_OWNER is the single match. Asserting SOCKET_IMPORT is a
    // real pattern rather than an empty one closes the last vacuous reading.
    expect(SOCKET_IMPORT.source.length).toBeGreaterThan(0);
    expect(scan().map((v) => v.pattern)).not.toContain("socket-choke-point-missing");
    expect(scan().map((v) => v.pattern)).not.toContain("socket-choke-point-duplicated");
  });
});

describe("host resolution is a count constraint, not a pure negative", () => {
  // Unlike the socket block above, the hostnames ARE written literally here.
  // The socket ban is unscoped, so naming the module specifier in this file
  // would be a violation the path exclusion happens to hide. The host count is
  // collected from src/ only, so a literal in a test is not a violation at all
  // — which is deliberate, and is what lets test/dav-discovery.test.ts build
  // fixture URLs against both hosts. A test that could not name the thing it is
  // testing would have to assert the pattern is non-empty and stop there.
  const owner = { file: DAV_HOST_OWNER, line: 30, column: 1 };
  const elsewhere = { file: "src/dav/calendar.ts", line: 7, column: 1 };

  it("passes when only the discovery module names a host", () => {
    expect(checkDavHostOwnership([owner])).toEqual([]);
  });

  it("reports a violation naming the offending file when anything else does", () => {
    const violations = checkDavHostOwnership([owner, elsewhere]);
    expect(violations.map((v) => v.pattern)).toEqual(["dav-host-outside-discovery"]);
    expect(violations[0]!.file).toBe(elsewhere.file);
  });

  it("reports a violation when nothing resolves a host at all", () => {
    // The direction a scoped negative cannot see: a discovery module quietly
    // deleted or renamed satisfies "no hardcoded host" trivially, by way of a
    // codebase that no longer works.
    expect(checkDavHostOwnership([]).map((v) => v.pattern)).toEqual([
      "dav-host-resolution-missing",
    ]);
  });

  it("matches both service hosts, and a sharded spelling of either", () => {
    // A shard constant is the realistic hardcoding — nobody copies the
    // unsharded root, they copy the home URL out of a diagnostic. Substring
    // matching is what makes the sharded form a violation too.
    for (const sample of [
      'const CALDAV = "https://caldav.icloud.com";',
      'const CARDDAV = "https://contacts.icloud.com";',
      'const HOME = "https://p120-caldav.icloud.com/00000000/calendars/";',
      'const BOOK = "https://p120-contacts.icloud.com/00000000/carddavhome/";',
    ]) {
      expect(
        new RegExp(DAV_HOST_LITERAL.source, DAV_HOST_LITERAL.flags).test(sample),
        `missed ${sample}`,
      ).toBe(true);
    }
  });

  it("does not match the mail host, which is a different ban on a different tree", () => {
    expect(
      new RegExp(DAV_HOST_LITERAL.source, DAV_HOST_LITERAL.flags).test(
        'connect({ hostname: "imap.mail.me.com", port: 993 });',
      ),
    ).toBe(false);
  });

  it("is wired into scan(): a tree with no such file fails", () => {
    // scripts/ contains no module naming a host, so scanning it exercises the
    // deleted direction against a real tree rather than a synthetic list.
    expect(scan("scripts").map((v) => v.pattern)).toContain("dav-host-resolution-missing");
    expect(scan().map((v) => v.pattern)).not.toContain("dav-host-resolution-missing");
    expect(scan().map((v) => v.pattern)).not.toContain("dav-host-outside-discovery");
  });
});

describe("the DAV transport choke point is a count constraint too", () => {
  const owner = { file: DAV_FETCH_OWNER, line: 235, column: 20 };
  const elsewhere = { file: "src/dav/calendar.ts", line: 12, column: 5 };

  it("passes when only the transport module reaches the network", () => {
    expect(checkDavFetchOwnership([owner])).toEqual([]);
  });

  it("reports a violation naming the offending file when a second module does", () => {
    const violations = checkDavFetchOwnership([owner, elsewhere]);
    expect(violations.map((v) => v.pattern)).toEqual(["dav-fetch-outside-transport"]);
    expect(violations[0]!.file).toBe(elsewhere.file);
  });

  it("reports a violation when no module reaches the network", () => {
    expect(checkDavFetchOwnership([]).map((v) => v.pattern)).toEqual([
      "dav-fetch-choke-point-missing",
    ]);
  });

  it("matches a bare call and a call through the global object", () => {
    for (const sample of [
      "response = await fetch(input, { ...init, headers, redirect: 'manual' });",
      "const r = await globalThis.fetch(url);",
    ]) {
      expect(
        new RegExp(DAV_FETCH_CALL.source, DAV_FETCH_CALL.flags).test(sample),
        `missed ${sample}`,
      ).toBe(true);
    }
  });

  it("does not match the injected transport, which differs only in case", () => {
    // Every DAV caller reaches the network THROUGH the injected function, and
    // that is the permitted form. A pattern that could not tell the two apart
    // would report every call site and be switched off within a week.
    for (const sample of [
      "const response = await davFetch(url, init);",
      "const books = await fetchAddressBooks({ account, headers: {}, fetch: davFetch });",
      "const responses = await propfind({ url, depth: '1', fetch: davFetch });",
      "export type DavFetch = typeof globalThis.fetch;",
    ]) {
      expect(
        new RegExp(DAV_FETCH_CALL.source, DAV_FETCH_CALL.flags).test(sample),
        `false-positived on ${sample}`,
      ).toBe(false);
    }
  });

  it("is wired into scan(): a tree with no such file fails", () => {
    expect(scan("scripts").map((v) => v.pattern)).toContain(
      "dav-fetch-choke-point-missing",
    );
    expect(scan().map((v) => v.pattern)).not.toContain("dav-fetch-choke-point-missing");
    expect(scan().map((v) => v.pattern)).not.toContain("dav-fetch-outside-transport");
  });
});

describe("the write choke point is a count constraint too", () => {
  // The write is the one thing this project does to the user's account, and
  // Convention 2 makes it deliberately singular: Claude drafts, the human
  // reviews and sends. A second module issuing the command is a second write
  // path arriving without a decision.
  const owner = { file: APPEND_OWNER, line: 2737, column: 7 };
  // The realistic second site, and it is realistic rather than hypothetical:
  // the tool layer is where "just write it from here" gets written, because
  // that is the layer holding the user's request.
  const elsewhere = { file: "src/mcp/tools/mail.ts", line: 41, column: 5 };

  it("passes when only the service module constructs the write command", () => {
    expect(checkAppendOwnership([owner])).toEqual([]);
  });

  it("reports a violation naming the offending file when a second module does", () => {
    const violations = checkAppendOwnership([owner, elsewhere]);
    expect(violations.map((v) => v.pattern)).toEqual(["append-outside-drafts"]);
    expect(violations[0]!.file).toBe(elsewhere.file);
  });

  it("reports a violation when no module constructs it at all", () => {
    // The direction a scoped negative cannot see: "no second write path" is
    // trivially true of a codebase with no write path, and losing the whole
    // capability is quieter than gaining a duplicate of it.
    expect(checkAppendOwnership([]).map((v) => v.pattern)).toEqual([
      "append-choke-point-missing",
    ]);
  });

  it("is wired into scan(): a tree with no write path fails", () => {
    // scripts/ constructs no command, so scanning it in isolation exercises the
    // deleted direction against a real tree rather than a synthetic list.
    expect(scan("scripts").map((v) => v.pattern)).toContain("append-choke-point-missing");
    expect(scan().map((v) => v.pattern)).not.toContain("append-choke-point-missing");
    expect(scan().map((v) => v.pattern)).not.toContain("append-outside-drafts");
  });

  it("matches the two shapes a command line is built in here", () => {
    // The known-violating samples for this constraint. A count constraint has
    // no entry on the pattern list, so the set-equality that guards the guard
    // for every other rule does not reach it — these stand in its place, for
    // the same stated reason: a pattern that silently matches nothing is
    // indistinguishable from a rule that was never added.
    for (const sample of [
      // The current construction site: after an interpolated tag.
      "`${tag} APPEND ${quotedMailbox} ${flags} {${message.byteLength}}`,",
      // The evasion a second writer would actually reach for, because it is
      // the shortest route: hand the whole line to the generic sender, which
      // supplies the tag itself.
      "await send(channel, `APPEND ${mailbox} (\\\\Draft) {${n}}`);",
      'const line = "APPEND INBOX {12}";',
    ]) {
      expect(
        new RegExp(APPEND_COMMAND.source, APPEND_COMMAND.flags).test(sample),
        `missed ${sample}`,
      ).toBe(true);
    }
  });

  it("does not fire on the reply, the identifiers, or the prose", () => {
    // Anchored on the construction rather than on the word, for the reason
    // DAV_FETCH_CALL is anchored on the call syntax. The success response code
    // carries the same six letters as a prefix, two constants contain them, and
    // three modules already discuss the command in prose. A rule that reported
    // any of those would be switched off within a week — and one that banned
    // reading the server's own reply would ban the answer to the very command
    // it protects.
    for (const sample of [
      'completion = "a5 OK [APPENDUID 1237268096 92] APPEND completed";',
      'expect(parseAppendUid("a5 OK APPEND completed")).toBeNull();',
      "if (bytes.byteLength > MAX_APPEND_LITERAL_BYTES) return null;",
      'export const DRAFT_APPEND_FLAGS = "(\\\\Draft \\\\Seen)";',
      " * decide which literal form `APPEND` may use. A tidied copy would be a",
    ]) {
      expect(
        new RegExp(APPEND_COMMAND.source, APPEND_COMMAND.flags).test(sample),
        `false-positived on ${sample}`,
      ).toBe(false);
    }
  });

  it("does fire on prose that spells the command out with an argument", () => {
    // Executable form of the discipline the rule's docstring states, and the
    // reason it is stated there rather than left to luck: the pattern being
    // case-sensitive and a comment happening to be lowercase is a coincidence,
    // not a property. Waves 5 through 8 add four more modules under src/, and
    // their plans ask them to discuss the write path in prose. Describe the
    // command by role, never by name — this is what it costs not to.
    expect(
      new RegExp(APPEND_COMMAND.source, APPEND_COMMAND.flags).test(
        " * an `APPEND that failed` must not delete the staged object.",
      ),
    ).toBe(true);
  });

  it("does not fire on the test that asserts the command line byte for byte", () => {
    // test/append.test.ts names the command in order to prove the exchange is
    // correct, and a fixture is not a code path. The scope is what holds that
    // apart, so this scans the REAL tree with exclusion disabled — if the scope
    // were widened to the full surface, the fixture would start failing commits
    // for asserting the very behaviour the rule protects.
    const withoutSkip = scan(undefined, NO_EXCLUSIONS);
    expect(withoutSkip.filter((v) => v.pattern === "append-outside-drafts")).toEqual([]);
    // Non-vacuous: with the skip disabled, test/ really was read.
    expect(withoutSkip.map((v) => v.file)).toContain(THIS_TEST_PATH);
    expect(APPEND_SCOPE).toBe("src/");
  });
});

describe("the subscription-feed fetch choke point is a count constraint too", () => {
  const owner = { file: SUBSCRIPTION_FEED_FETCH_OWNER, line: 90, column: 14 };
  const elsewhere = { file: "src/dav/calendar.ts", line: 12, column: 5 };

  it("passes when only the subscription-feed module reaches the network", () => {
    expect(checkSubscriptionFeedFetchOwnership([owner])).toEqual([]);
  });

  it("reports a violation naming the offending file when a second module does", () => {
    const violations = checkSubscriptionFeedFetchOwnership([owner, elsewhere]);
    expect(violations.map((v) => v.pattern)).toEqual([
      "subscription-feed-fetch-outside-owner",
    ]);
    expect(violations[0]!.file).toBe(elsewhere.file);
  });

  it("reports a violation when no module reaches the network", () => {
    expect(checkSubscriptionFeedFetchOwnership([]).map((v) => v.pattern)).toEqual([
      "subscription-feed-fetch-choke-point-missing",
    ]);
  });

  it("matches a bare call and a call through the global object", () => {
    for (const sample of [
      "response = await fetch(url);",
      "const r = await globalThis.fetch(url);",
    ]) {
      expect(
        new RegExp(
          SUBSCRIPTION_FEED_FETCH_CALL.source,
          SUBSCRIPTION_FEED_FETCH_CALL.flags,
        ).test(sample),
        `missed ${sample}`,
      ).toBe(true);
    }
  });

  it("does not match the injected fetcher, which differs only in case", () => {
    for (const sample of [
      "const text = await fetchSubscriptionFeed(collection.source);",
      "export type FetchSubscriptionFeed = typeof fetchSubscriptionFeed;",
    ]) {
      expect(
        new RegExp(
          SUBSCRIPTION_FEED_FETCH_CALL.source,
          SUBSCRIPTION_FEED_FETCH_CALL.flags,
        ).test(sample),
        `false-positived on ${sample}`,
      ).toBe(false);
    }
  });

  it("is wired into scan(): a tree with no such file fails", () => {
    expect(scan("scripts").map((v) => v.pattern)).toContain(
      "subscription-feed-fetch-choke-point-missing",
    );
    expect(scan().map((v) => v.pattern)).not.toContain(
      "subscription-feed-fetch-choke-point-missing",
    );
    expect(scan().map((v) => v.pattern)).not.toContain(
      "subscription-feed-fetch-outside-owner",
    );
  });
});

describe("the single reader of the grant's props is a count constraint too (Phase 9 D-22)", () => {
  // The spelled read IS written literally here, as the hostnames are in the
  // host block above. The pattern is collected from src/ only, and this file
  // is skipped by path for every rule, so nothing here can trip the count.
  const owner = { file: PROPS_READER_OWNER, line: 293, column: 25 };
  const elsewhere = { file: "src/mcp/server.ts", line: 40, column: 9 };

  /** A fresh copy per probe, so no state can carry between samples. */
  const fires = (sample: string): boolean =>
    new RegExp(PROPS_READER.source, PROPS_READER.flags).test(sample);

  it("passes when the door is the only file that reads the grant's props", () => {
    expect(checkPropsReaderOwnership([owner])).toEqual([]);
  });

  it("reports a violation naming the second file when another module reads them", () => {
    const violations = checkPropsReaderOwnership([owner, elsewhere]);
    expect(violations.map((v) => v.pattern)).toEqual(["props-reader-outside-owner"]);
    expect(violations[0]!.file).toBe(elsewhere.file);
    expect(violations[0]!.line).toBe(elsewhere.line);
  });

  it("reports a violation naming the owner when no file reads them", () => {
    // The direction a negative cannot see: a door that stopped reading the
    // grant serves every grant, and nothing fails on the way out.
    const violations = checkPropsReaderOwnership([]);
    expect(violations.map((v) => v.pattern)).toEqual(["props-reader-missing"]);
    expect(violations[0]!.file).toBe(PROPS_READER_OWNER);
  });

  it("names the door as the owner, and collects from the source tree only", () => {
    expect(PROPS_READER_OWNER).toBe("src/mcp/api-handler.ts");
    expect(PROPS_READER_SCOPE).toBe("src/");
  });

  it("matches the props read off the request context", () => {
    for (const sample of [
      "if (!isOwnerGrant(ctx.props)) {",
      "const grant = ctx.props;",
      "const id = ctx.props.userId;",
      "const grant = ctx?.props;",
      "return this.ctx.props;",
      " * `ctx.props` with it.",
      // Code review WR-03. The shapes the bare-dot text missed. The non-null
      // mark is the one that mattered: it is the natural spelling for a
      // context parameter typed as possibly absent, and there is no compiler
      // backstop on this count.
      "const grant = ctx!.props;",
      "const grant = ctx\n  .props;",
      "const grant = ctx\n  ?.props;",
      "const grant = ctx ! . props;",
    ]) {
      expect(fires(sample), `missed ${sample}`).toBe(true);
    }
  });

  it("agrees with the account-binding ban about the member access (code review WR-03)", () => {
    // The two were written in the same phase and disagreed for no reason. A
    // difference between them is a difference nobody decided, so it is pinned
    // here rather than left to be noticed. The text is written out, so this
    // cannot pass by reading one pattern twice.
    //
    // The other one was a COUNT beside this one until phase 13 deleted the
    // binding it counted the readers of. The member access outlived the count,
    // so the agreement is still worth pinning — but the pattern now lives in the
    // rule list rather than in an exported constant, and it is read back by id.
    const SHARED_MEMBER_ACCESS = "\\s*(?:[?!]\\s*)?\\.\\s*";
    const bindingBan = FORBIDDEN.find((one) => one.id === "mail-secret-read")!;
    expect(
      PROPS_READER.source.includes(SHARED_MEMBER_ACCESS),
      "the props count no longer spells the shared member access",
    ).toBe(true);
    expect(
      bindingBan.pattern.source.includes(SHARED_MEMBER_ACCESS),
      "the account-binding ban no longer spells the shared member access",
    ).toBe(true);
  });

  it("matches a call to the auth context reader, the other way to the same props", () => {
    // Beyond D-22's wording, and it only refuses more. To drop the arm, delete
    // it from the pattern and delete this test and the import row below.
    for (const sample of [
      "const auth = getMcpAuthContext();",
      "const grant = getMcpAuthContext ()?.props;",
    ]) {
      expect(fires(sample), `missed ${sample}`).toBe(true);
    }
  });

  it("does not match an import of the auth context reader, only a call to it", () => {
    expect(fires('import { getMcpAuthContext } from "agents/mcp";')).toBe(false);
  });

  it("does not match the bare word, a DAV props field, or a look-alike", () => {
    for (const sample of [
      // The DAV library's PROPFIND results, all over src/dav/.
      "const name = response.props?.displayname;",
      "for (const [key, value] of Object.entries(result.props)) {",
      "const props = [`${DAVNamespaceShort.DAV}:displayname`];",
      // A props member on some other object.
      "const grant = request.props;",
      "const grant = authInfo.props;",
      // The context under a longer name: a known evasion, pinned as unseen.
      "const grant = myctx.props;",
      // A longer member that merely starts with the word.
      "const table = ctx.propsById;",
      "const table = ctx.props_cache;",
      // The props CONSTRUCTOR, which is a different question and now has a
      // count of its own — `PRINCIPAL_CONSTRUCTOR`, two owners, the block
      // further down this file. This count is about files that READ the props
      // off the execution context; that one is about sites that MINT a
      // principal from a props object. Neither answers the other, which is why
      // Phase 11 built a separate count rather than the arm the old note here
      // asked for.
      "const principal = principalFromProps(grant);",
      "export function principalFromProps(props: unknown): Principal {",
    ]) {
      expect(fires(sample), `false-positived on ${sample}`).toBe(false);
    }
  });

  it("pins the known evasions as unseen, so nobody believes they are covered", () => {
    // Each of these DOES read the grant's props. The docstring lists them. If
    // the pattern later starts to see one, this goes red: move the row out and
    // update the docstring.
    for (const sample of [
      "const { props } = ctx;",
      "const grant = context.props;",
      'const grant = ctx["props"];',
      // Code review WR-03. The cast puts the cast keyword between the name and
      // the dot, so the widened member access still cannot reach it.
      "const grant = (ctx as ExecutionContext).props;",
    ]) {
      expect(fires(sample), `now sees ${sample}`).toBe(false);
    }
  });

  it("carries no global flag, because scan() takes the first match with search()", () => {
    expect(PROPS_READER.flags).toBe("");
  });

  it("is wired into scan(): a tree with no owner file fails", () => {
    // scripts/ is outside PROPS_READER_SCOPE, so scanning it alone exercises
    // the deleted direction against a real tree rather than a synthetic list.
    expect(scan("scripts").map((v) => v.pattern)).toContain("props-reader-missing");
  });

  it("passes on the real tree: the door is the one reader", () => {
    const patterns = scan().map((v) => v.pattern);
    expect(patterns).not.toContain("props-reader-missing");
    expect(patterns).not.toContain("props-reader-outside-owner");
  });
});

describe("the two readers of the password are a count constraint with two owners (Phase 9 D-03, D-25)", () => {
  // The spelled import IS written literally here, as the props read is in the
  // block above. The pattern is collected from src/ only, and this file is
  // skipped by path for every rule, so nothing here can trip the count.
  const [mailOwnerPath, davOwnerPath] = PASSWORD_READER_OWNERS as readonly [string, string];
  const mailOwner = { file: mailOwnerPath, line: 29, column: 1 };
  const davOwner = { file: davOwnerPath, line: 29, column: 1 };
  const outsider = { file: "src/mcp/tools/mail.ts", line: 12, column: 1 };

  /** A fresh copy per probe, so no state can carry between samples. */
  const fires = (sample: string): boolean =>
    new RegExp(PASSWORD_READER_IMPORT.source, PASSWORD_READER_IMPORT.flags).test(sample);

  it("names exactly the mail login and the DAV header as owners, in that order", () => {
    expect([...PASSWORD_READER_OWNERS]).toEqual([
      "src/mail/credentials.ts",
      "src/dav/transport.ts",
    ]);
    expect(PASSWORD_READER_SCOPE).toBe("src/");
  });

  it("two: passes when both owners import the reader and nothing else does", () => {
    expect(checkPasswordReaderOwnership([mailOwner, davOwner])).toEqual([]);
    // Order in the list is the walk order of the tree, so it must not matter.
    expect(checkPasswordReaderOwnership([davOwner, mailOwner])).toEqual([]);
  });

  it("one: reports the DAV owner as missing when only the mail owner imports it", () => {
    const violations = checkPasswordReaderOwnership([mailOwner]);
    expect(violations.map((v) => v.pattern)).toEqual(["password-reader-missing"]);
    expect(violations[0]!.file).toBe(davOwnerPath);
    expect(violations[0]!.why).toContain(davOwnerPath);
  });

  it("one: reports the mail owner as missing when only the DAV owner imports it", () => {
    const violations = checkPasswordReaderOwnership([davOwner]);
    expect(violations.map((v) => v.pattern)).toEqual(["password-reader-missing"]);
    expect(violations[0]!.file).toBe(mailOwnerPath);
    expect(violations[0]!.why).toContain(mailOwnerPath);
  });

  it("zero: reports two missing violations, one naming each owner", () => {
    // The direction a negative cannot see, and the reason a one-owner checker
    // cannot be copied: an empty list is TWO login paths gone, not one.
    const violations = checkPasswordReaderOwnership([]);
    expect(violations.map((v) => v.pattern)).toEqual([
      "password-reader-missing",
      "password-reader-missing",
    ]);
    expect(violations.map((v) => v.file)).toEqual([mailOwnerPath, davOwnerPath]);
  });

  it("three: reports one outside violation naming the third file", () => {
    const violations = checkPasswordReaderOwnership([mailOwner, davOwner, outsider]);
    expect(violations.map((v) => v.pattern)).toEqual(["password-reader-outside-owners"]);
    expect(violations[0]!.file).toBe(outsider.file);
    expect(violations[0]!.line).toBe(outsider.line);
  });

  it("one owner plus an outsider: reports one of each, so a moved reader is not a pass", () => {
    // Two importers is the right NUMBER and the wrong answer. The count is of
    // these two files, not of any two files.
    const violations = checkPasswordReaderOwnership([mailOwner, outsider]);
    expect(violations.map((v) => v.pattern).sort()).toEqual([
      "password-reader-missing",
      "password-reader-outside-owners",
    ]);
    const missing = violations.find((v) => v.pattern === "password-reader-missing")!;
    const outside = violations.find((v) => v.pattern === "password-reader-outside-owners")!;
    expect(missing.file).toBe(davOwnerPath);
    expect(outside.file).toBe(outsider.file);
  });

  it("gives the two ids distinct sort keys, straight after the props count's", () => {
    const violations = checkPasswordReaderOwnership([mailOwner, outsider]);
    const outside = violations.find((v) => v.pattern === "password-reader-outside-owners")!;
    const missing = violations.find((v) => v.pattern === "password-reader-missing")!;
    expect(outside.patternIndex).toBe(FORBIDDEN.length + 12);
    expect(missing.patternIndex).toBe(FORBIDDEN.length + 13);
  });

  it("matches the real import lines of both owners, and the other ways to write one", () => {
    for (const sample of [
      // The line both owners carry today, byte for byte.
      'import { passwordOf } from "../principal";',
      // Beside other names, and as a type-only import.
      'import { type Principal, passwordOf } from "../principal";',
      'import type { passwordOf } from "../principal";',
      'import { type passwordOf } from "../principal";',
      // Spread over three lines.
      'import {\n  passwordOf,\n} from "../principal";',
      'import {\n  appleIdOf,\n  passwordOf,\n  type Principal,\n} from "../../principal";',
      // An explicit extension, single quotes, a deeper path.
      "import { passwordOf } from '../principal.ts';",
      'import { passwordOf } from "../../principal.js";',
      'import { passwordOf } from "./principal.mjs";',
      // A renamed binding still spells the reader's name in the braces.
      'import { passwordOf as readSecret } from "../principal";',
      // Comments count, as they do for every count.
      ' * import { passwordOf } from "../principal" is how the reader arrives.',
    ]) {
      expect(fires(sample), `missed ${JSON.stringify(sample)}`).toBe(true);
    }
  });

  it("does not match another name, another module, or the bare word", () => {
    for (const sample of [
      // Another name from the principal module.
      'import { appleIdOf } from "../principal";',
      // A RETIRED name, kept on purpose. This was the environment-backed
      // constructor until phase 13 deleted it, so no import of it can exist in
      // the tree any more — which is exactly what makes it a good control here:
      // the pattern must fire on the password reader's name and on nothing else
      // that could sit beside it in the same braces, whether or not that other
      // name still resolves to anything.
      'import { type Principal, principalFromEnv } from "../principal";',
      // A longer identifier that merely contains the reader's name.
      'import { passwordOfTheDay } from "../principal";',
      'import { myPasswordOf } from "../principal";',
      // The reader's name from a module that is not the principal module.
      'import { passwordOf } from "../credentials";',
      'import { passwordOf } from "../principals";',
      'import { passwordOf } from "../principal-helpers";',
      'import { passwordOf } from "../myprincipal";',
      // The bare word: a call, a definition, a comment.
      "const password = passwordOf(principal);",
      "export function passwordOf(principal: Principal): string {",
      "// `passwordOf` is the one reader.",
      // Two imports side by side: the braces of one never reach the other.
      'import { appleIdOf } from "../principal";\nimport { passwordOf } from "../credentials";',
    ]) {
      expect(fires(sample), `false-positived on ${JSON.stringify(sample)}`).toBe(false);
    }
  });

  it("pins the known evasions as unseen, so nobody believes they are covered", () => {
    // Each of these DOES reach the reader. The docstring lists all four. If the
    // pattern later starts to see one, this goes red: move the row out and
    // update the docstring.
    for (const sample of [
      'import * as principal from "../principal";',
      'export { passwordOf } from "../principal";',
      'const { passwordOf } = await import("../principal");',
      'import { passwordOf } from "#principal";',
    ]) {
      expect(fires(sample), `now sees ${JSON.stringify(sample)}`).toBe(false);
    }
  });

  it("collects a file that imports the reader twice once, at its first import", () => {
    // scan() takes `contents.search(pattern)`: one index per file, the first.
    // The count is of distinct file paths, so a second import in the same file
    // adds nothing to it.
    const first = 'import { passwordOf } from "../principal";';
    const twice = `// header\n${first}\nimport { passwordOf as again } from "../principal";\n`;
    expect(PASSWORD_READER_IMPORT.flags).toBe("");
    expect(twice.search(PASSWORD_READER_IMPORT)).toBe(twice.indexOf(first));
    // Without the global flag, match() is the first match and no more.
    expect(twice.match(PASSWORD_READER_IMPORT)).toHaveLength(1);
    // Both owners are still one entry each on the real tree.
    const patterns = scan().map((v) => v.pattern);
    expect(patterns).not.toContain("password-reader-outside-owners");
  });

  it("is wired into scan(): a tree with neither owner reports both as missing", () => {
    // scripts/ is outside PASSWORD_READER_SCOPE, so scanning it alone exercises
    // the deleted direction against a real tree rather than a synthetic list.
    const missing = scan("scripts").filter((v) => v.pattern === "password-reader-missing");
    expect(missing.map((v) => v.file).sort()).toEqual([...PASSWORD_READER_OWNERS].sort());
  });

  it("passes on the real tree: the two owners are the two importers", () => {
    const patterns = scan().map((v) => v.pattern);
    expect(patterns).not.toContain("password-reader-missing");
    expect(patterns).not.toContain("password-reader-outside-owners");
  });
});

describe("a read of either deleted account binding is banned outright (CUT-01)", () => {
  // The spelled read IS written literally here, as the props read and the
  // password import are in the blocks above. The rule is scoped to src/ and this
  // file is skipped by path for every rule, so nothing here can trip it. No
  // sample below sits inside a logging call: that would fire four other rules
  // and prove none of this one.
  //
  // THIS WAS A COUNT UNTIL PHASE 13, with the principal module named as its one
  // permitted reader. That reader is deleted, so zero became the correct number
  // and the count's missing arm could never fire again — which this project
  // treats as indistinguishable from a constraint that was never added. The
  // pattern moved across unchanged, so every sample row below is the same row it
  // was; what changed is the shape of the rule around it.
  //
  // The pattern is read back out of the list BY ID rather than off an exported
  // constant, because the ban has no constant of its own. That is also what
  // keeps the member-access assertion further up this file honest.
  const rule = FORBIDDEN.find((one) => one.id === "mail-secret-read")!;

  /** A fresh copy per probe, so no state can carry between samples. */
  const fires = (sample: string): boolean =>
    new RegExp(rule.pattern.source, rule.pattern.flags.replace("g", "")).test(
      sample,
    );

  it("exists, is scoped to the source tree, and is global", () => {
    // Scoped, because tests bind their own fakes and a test is not a credential
    // path. Global, because every other entry in the list is: `scan()` walks a
    // rule with `matchAll`, and a rule without the flag would loop forever.
    expect(rule).toBeDefined();
    expect(rule.scope).toBe("src/");
    expect(rule.pattern.flags).toContain("g");
  });

  it("says in its reason why a read of a DELETED binding is refused at all", () => {
    // The one thing a reader of this rule cannot work out for themselves. The
    // binding is gone, so the obvious question is what there is left to protect,
    // and the answer is in the reason rather than in a planning file.
    expect(rule.why).toContain("deleted");
    expect(rule.why.length).toBeGreaterThan(400);
  });

  it("matches a read of either deleted binding off the environment object", () => {
    for (const sample of [
      "  const appleId = env.APPLE_ID;",
      "  const appPassword = env.APPLE_APP_PASSWORD;",
      "return this.env.APPLE_ID;",
      "if (!isConfiguredSecret(env.APPLE_APP_PASSWORD)) return;",
      " * reads `env.APPLE_ID` before anything else.",
      // Code review WR-03. The shapes the bare-dot text missed, and the reason
      // this rule and the props count spell the member access the same way.
      "const appleId = env?.APPLE_ID;",
      "const appleId = env!.APPLE_ID;",
      "const appleId = env\n  .APPLE_ID;",
      "const appleId = env ! . APPLE_APP_PASSWORD;",
    ]) {
      expect(fires(sample), `missed ${sample}`).toBe(true);
    }
  });

  it("does not match the login gate's own secret (D-28)", () => {
    // It was never an Apple credential and it had its own single reader in the
    // login gate. It was out of the count for that reason and it is out of the
    // ban for the same one. If this ever starts matching, the rule has been
    // widened to answer a second question and its comment block is no longer
    // true.
    for (const sample of [
      "if (!isConfiguredSecret(env.AUTH_SECRET)) {",
      "await secretMatches(submitted, env.AUTH_SECRET)",
    ]) {
      expect(fires(sample), `now sees ${sample}`).toBe(false);
    }
  });

  it("does not match a look-alike, a field declaration, or a principal's field", () => {
    for (const sample of [
      // A longer identifier that merely starts with a binding name.
      "const cached = env.APPLE_ID_CACHE;",
      "const legacy = env.APPLE_APP_PASSWORD_V1;",
      // A field on the principal, which is the shape everything now uses.
      "const address = principal.appleId;",
      // A type field declaration. No type in the repository spells either name
      // any more, but a pattern that fired on one would fire on a planning
      // artifact quoted into a comment.
      "  APPLE_ID: string | undefined;",
      "  APPLE_APP_PASSWORD: string | undefined;",
      // The bare name in prose, with no environment object in front of it.
      " * Apple ID used for IMAP authentication. Workers Secret.",
      // Another object's field of the same name.
      "const value = bindings.APPLE_ID;",
    ]) {
      expect(fires(sample), `false-positived on ${sample}`).toBe(false);
    }
  });

  it("pins the known evasions as unseen, so nobody believes they are covered", () => {
    // Each of these DOES read a deleted binding. The rule's comment block lists
    // them, and says the compiler is the first check for all of them (D-14). If
    // the pattern later starts to see one, this goes red: move the row out and
    // update the comment block.
    for (const sample of [
      "const { APPLE_ID } = env;",
      'const value = env["APPLE_ID"];',
      // Code review WR-03. The cast puts the cast keyword between the name and
      // the dot, so the widened member access still cannot reach it.
      "const value = (env as MailSecrets).APPLE_ID;",
    ]) {
      expect(fires(sample), `now sees ${sample}`).toBe(false);
    }
  });

  it("is wired into scan(): it is in the list scan() walks, and its global form matches", () => {
    // The count it replaced proved its wiring by scanning a tree with no owner
    // file, which a ban has no equivalent of. So the wiring is proved the way
    // every other ban in this file is: the rule is reached by id out of the very
    // array `scan()` iterates — `FORBIDDEN.find` above would have thrown on a
    // missing id — and its GLOBAL form is exercised here, because `scan()` walks
    // a rule with `matchAll` and a rule whose flag went missing would loop for
    // ever rather than fail.
    //
    // Its known-violating sample is held by the set-equality in "the patterns
    // have teeth" further up, which is absolute in both directions: a rule
    // without a sample fails that test by construction. Nothing is asserted twice
    // here.
    expect(FORBIDDEN.some((one) => one.id === "mail-secret-read")).toBe(true);
    expect([
      ..."  const appleId = env.APPLE_ID;".matchAll(rule.pattern),
    ]).toHaveLength(1);
  });

  it("fires on a comment and on a string that spell the read, and that is a recorded choice", () => {
    // Every line here is INNOCENT: not one performs a read. The rule fires on
    // all of them anyway, because it is anchored on the words and reads text
    // rather than syntax. That over-match is kept on purpose, and this case is
    // what makes it a known limit rather than a surprise on somebody's commit.
    //
    // It is also the whole reason `src/principal.ts` and `src/env.ts` describe
    // the read by ROLE. Those two files used to spell both names in their
    // headers; a header that still did would fail the check it was explaining,
    // which is the same trap the banned-transport and write rules set.
    //
    // If this goes red, someone narrowed the rule. The fix for an innocent hit
    // is to describe the read by role in the prose. Never make the rule see
    // less.
    const innocentButRefused: ReadonlyArray<readonly [string, string]> = [
      ["a comment that spells the read", " * it used to read env.APPLE_ID here."],
      [
        "a string that spells the read",
        'const hint = "nothing may read env.APPLE_APP_PASSWORD";',
      ],
    ];
    expect(innocentButRefused.length).toBe(2);
    for (const [shape, line] of innocentButRefused) {
      expect(fires(line), `the rule no longer fires on ${shape}: it was narrowed`).toBe(
        true,
      );
    }

    // The hook prints the reason text, so it has to tell the author what to do
    // about an innocent hit rather than leaving them to guess.
    expect(rule.why).toContain("by role");
    expect(rule.why).toContain("Do not narrow the pattern");
  });

  it("passes on the real tree: nothing under the source tree reads either", () => {
    // The measured-zero claim in the rule's comment block, measured rather than
    // asserted. This is the assertion that would have gone red before phase 13
    // deleted the reader, and it is why the rule could not have been added
    // earlier.
    expect(scan().map((v) => v.pattern)).not.toContain("mail-secret-read");
  });
});

describe("one function turns an address into a user id (D-18, ISO-05 rule 10)", () => {
  const owner = { file: ADDRESS_HASH_OWNER, line: 151, column: 18 };
  const elsewhere = { file: "src/dav/discovery.ts", line: 142, column: 18 };

  /** A fresh copy per probe, so no state can carry between samples. */
  const fires = (sample: string): boolean =>
    new RegExp(ADDRESS_HASH.source, ADDRESS_HASH.flags).test(sample);

  it("passes when the owner is the only file that hashes an address", () => {
    expect(checkAddressHashOwnership([owner])).toEqual([]);
  });

  it("reports a violation naming the second file when another module hashes one", () => {
    const violations = checkAddressHashOwnership([owner, elsewhere]);
    expect(violations.map((v) => v.pattern)).toEqual([
      "address-hashing-site-outside-owner",
    ]);
    expect(violations[0]!.file).toBe(elsewhere.file);
    expect(violations[0]!.line).toBe(elsewhere.line);
    expect(violations[0]!.column).toBe(elsewhere.column);
  });

  it("reports a violation naming the owner when no file hashes one", () => {
    // The direction a negative cannot see. "No second producer" is trivially
    // true of a tree with no producer left, and nothing goes red on the way
    // out: the tests that covered the deleted code leave with it.
    const violations = checkAddressHashOwnership([]);
    expect(violations.map((v) => v.pattern)).toEqual(["address-hashing-site-missing"]);
    expect(violations[0]!.file).toBe(ADDRESS_HASH_OWNER);
    expect(violations[0]!.line).toBe(0);
    expect(violations[0]!.column).toBe(0);
  });

  it("names the one producer, and collects from the source tree only", () => {
    expect(ADDRESS_HASH_OWNER).toBe("src/principal.ts");
    expect(ADDRESS_HASH_SCOPE).toBe("src/");
  });

  it("matches the owner's own hashing site, on one line and split across several", () => {
    for (const sample of [
      // src/principal.ts as it is written today.
      '  const digest = await crypto.subtle.digest("SHA-256", ENCODER.encode(folded));',
      // The same call after a formatter breaks it up. The character class
      // matches newlines, which is what keeps this seen.
      '  const digest = await crypto.subtle.digest(\n    "SHA-256",\n    ENCODER.encode(folded),\n  );',
      // White space between the call and its parenthesis.
      '  await crypto.subtle.digest ( "SHA-256", ENCODER.encode(address) );',
    ]) {
      expect(fires(sample), `missed ${sample}`).toBe(true);
    }
  });

  it("does not match the three change-hash sites in the confirm module", () => {
    // These are the rows a MISSING WORD BOUNDARY silently catches. The confirm
    // module's encoder ends with the owner's encoder name, and the character
    // in front of it is a word character, so the boundary fails there. Without
    // these rows the block passes just as happily with a broken anchor as with
    // a correct one — and a broken anchor reports a second owner, which the
    // pre-commit hook turns into a refusal of every commit in the repository.
    for (const sample of [
      '  const digest = await crypto.subtle.digest(\n    "SHA-256",\n    TOKEN_ENCODER.encode(canonicalChange(change)),\n  );',
      '    crypto.subtle.digest("SHA-256", TOKEN_ENCODER.encode(a)),',
      '    crypto.subtle.digest("SHA-256", TOKEN_ENCODER.encode(b)),',
    ]) {
      expect(fires(sample), `now sees ${sample}`).toBe(false);
    }
  });

  it("does not match the two gate-secret sites in the login handler (D-28)", () => {
    // These are the rows a CASE-INSENSITIVE FLAG silently catches. The login
    // gate's encoder is a function-local lower-case name. What it hashes is
    // the submitted secret, which is neither an address nor a user id, and
    // Phase 9 D-28 set the precedent for narrowing rather than folding: one
    // count answering two questions answers neither well.
    for (const sample of [
      '  const submittedDigest = await crypto.subtle.digest(\n    "SHA-256",\n    encoder.encode(submitted),\n  );',
      '  const expectedDigest = await crypto.subtle.digest(\n    "SHA-256",\n    encoder.encode(expected),\n  );',
    ]) {
      expect(fires(sample), `now sees ${sample}`).toBe(false);
    }
  });

  it("keeps the word boundary and the absence of a case flag as asserted properties", () => {
    // Not merely described in the docstring. The boundary is also shown doing
    // work: an unbounded copy of the same name DOES reach inside the longer
    // one, so a boundary that silently stopped mattering is distinguishable
    // from one that is load-bearing.
    expect(ADDRESS_HASH.flags).toBe("");
    expect(ADDRESS_HASH.source).toContain("\\b");
    expect(new RegExp("\\bENCODER\\b").test("TOKEN_ENCODER")).toBe(false);
    expect(new RegExp("ENCODER").test("TOKEN_ENCODER")).toBe(true);
  });

  it("pins the known evasions as unseen, so nobody believes they are covered", () => {
    // Each of these DOES turn an address into an id. The docstring lists them.
    // If the pattern later starts to see one, this goes red: move the row out
    // and update the docstring.
    for (const sample of [
      // 1. the encoder renamed
      '  const digest = await crypto.subtle.digest("SHA-256", UTF8.encode(folded));',
      // 2. an encoder constructed inline at the call
      '  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(folded));',
      // 3. hashed by a library rather than by Web Crypto
      "  const digest = await sha256(folded);",
    ]) {
      expect(fires(sample), `now sees ${sample}`).toBe(false);
    }
  });

  it("is wired into scan(): a tree with no producer reports the owner as missing", () => {
    // scripts/ is outside ADDRESS_HASH_SCOPE, so scanning it alone exercises
    // the deleted direction against a real tree rather than a synthetic list.
    expect(scan("scripts").map((v) => v.pattern)).toContain(
      "address-hashing-site-missing",
    );
  });

  it("passes on the real tree: exactly one producer, and it is the owner", () => {
    const patterns = scan().map((v) => v.pattern);
    expect(patterns).not.toContain("address-hashing-site-missing");
    expect(patterns).not.toContain("address-hashing-site-outside-owner");
  });
});

describe("the two sites that mint a principal are a count constraint with two owners (Phase 11)", () => {
  // The constructor's name IS written literally here, as the props read and the
  // spelled import are in the blocks above. The pattern is collected from src/
  // only, and this file is skipped by path for every rule, so nothing here can
  // trip the count.
  const [doorPath, loginPath] = PRINCIPAL_CONSTRUCTOR_OWNERS as readonly [
    string,
    string,
  ];
  const door = { file: doorPath, line: 383, column: 25 };
  const login = { file: loginPath, line: 1271, column: 31 };
  const outsider = { file: "src/mcp/tools/mail.ts", line: 12, column: 1 };

  /** A fresh copy per probe, so no state can carry between samples. */
  const fires = (sample: string): boolean =>
    new RegExp(PRINCIPAL_CONSTRUCTOR.source, PRINCIPAL_CONSTRUCTOR.flags).test(
      sample,
    );

  it("names exactly the door and the login page as owners, in that order", () => {
    expect([...PRINCIPAL_CONSTRUCTOR_OWNERS]).toEqual([
      "src/mcp/api-handler.ts",
      "src/auth/login-handler.ts",
    ]);
    expect(PRINCIPAL_CONSTRUCTOR_SCOPE).toBe("src/");
  });

  it("two: passes when both owners call the constructor and nothing else does", () => {
    expect(checkPrincipalConstructorOwnership([door, login])).toEqual([]);
    // Order in the list is the walk order of the tree, so it must not matter.
    expect(checkPrincipalConstructorOwnership([login, door])).toEqual([]);
  });

  it("one: reports the login page as missing when only the door calls it", () => {
    const violations = checkPrincipalConstructorOwnership([door]);
    expect(violations.map((v) => v.pattern)).toEqual([
      "principal-constructor-missing",
    ]);
    expect(violations[0]!.file).toBe(loginPath);
    expect(violations[0]!.why).toContain(loginPath);
  });

  it("one: reports the door as missing when only the login page calls it", () => {
    const violations = checkPrincipalConstructorOwnership([login]);
    expect(violations.map((v) => v.pattern)).toEqual([
      "principal-constructor-missing",
    ]);
    expect(violations[0]!.file).toBe(doorPath);
    expect(violations[0]!.why).toContain(doorPath);
  });

  it("zero: reports two missing violations, one naming each owner", () => {
    // The direction a negative cannot see, and the reason a one-owner checker
    // could not be copied: an empty list is TWO identity paths gone, not one.
    // The door losing its call is the Phase 11 switch coming undone.
    const violations = checkPrincipalConstructorOwnership([]);
    expect(violations.map((v) => v.pattern)).toEqual([
      "principal-constructor-missing",
      "principal-constructor-missing",
    ]);
    expect(violations.map((v) => v.file)).toEqual([doorPath, loginPath]);
  });

  it("three: reports one outside violation naming the third file", () => {
    const violations = checkPrincipalConstructorOwnership([
      door,
      login,
      outsider,
    ]);
    expect(violations.map((v) => v.pattern)).toEqual([
      "principal-constructor-outside-owners",
    ]);
    expect(violations[0]!.file).toBe(outsider.file);
    expect(violations[0]!.line).toBe(outsider.line);
  });

  it("one owner plus an outsider: reports one of each, so a moved minter is not a pass", () => {
    // Two callers is the right NUMBER and the wrong answer. The count is of
    // these two files, not of any two files.
    const violations = checkPrincipalConstructorOwnership([door, outsider]);
    expect(violations.map((v) => v.pattern).sort()).toEqual([
      "principal-constructor-missing",
      "principal-constructor-outside-owners",
    ]);
    const missing = violations.find(
      (v) => v.pattern === "principal-constructor-missing",
    )!;
    const outside = violations.find(
      (v) => v.pattern === "principal-constructor-outside-owners",
    )!;
    expect(missing.file).toBe(loginPath);
    expect(outside.file).toBe(outsider.file);
  });

  it("gives the two ids distinct sort keys, straight after the address-hash count's", () => {
    const violations = checkPrincipalConstructorOwnership([door, outsider]);
    const outside = violations.find(
      (v) => v.pattern === "principal-constructor-outside-owners",
    )!;
    const missing = violations.find(
      (v) => v.pattern === "principal-constructor-missing",
    )!;
    expect(outside.patternIndex).toBe(FORBIDDEN.length + 16);
    expect(missing.patternIndex).toBe(FORBIDDEN.length + 17);
  });

  it("matches the real call lines of both owners, and the other ways to write one", () => {
    for (const sample of [
      // The two lines the owners carry today, byte for byte.
      "      const principal = principalFromProps(ctx.props);",
      "      const principal = await principalFromProps({",
      // Returned, awaited, or handed straight on.
      "return principalFromProps(props);",
      "await principalFromProps(grant);",
      "buildRequestHandler(principalFromProps(ctx.props));",
      // Space before the parenthesis, and a call broken across lines.
      "principalFromProps (grant);",
      "principalFromProps(\n  props,\n);",
      // Through a namespace import. Seen, and only refuses more.
      "const principal = principal_module.principalFromProps(props);",
      // Comments count, as they do for every count.
      " * principalFromProps(grant) is how the principal arrives.",
    ]) {
      expect(fires(sample), `missed ${sample}`).toBe(true);
    }
  });

  it("does not match the constructor's own definition, or a mention with no call", () => {
    for (const sample of [
      // The definition in the principal module, byte for byte. This is the one
      // that matters: without the lookbehind the defining file is a third
      // "caller" and the count freezes the repository.
      "export async function principalFromProps(props: unknown): Promise<Principal> {",
      "function principalFromProps(props) {",
      "async function principalFromProps(props) {",
      // A definition the formatter broke after the keyword.
      "export async function\n  principalFromProps(props: unknown) {",
      // A plain named import: no parenthesis after the name.
      'import { normaliseAppleId, principalFromProps, userIdOf } from "../principal";',
      'import { principalFromProps } from "../principal";',
      // Prose naming it without calling it, which both owners and the door's
      // own comments already do.
      " * `principalFromProps` is the ONE constructor, and it refuses first.",
      " * `principalFromProps` makes the same choice one module over.",
      // A longer name that merely starts with it.
      "principalFromPropsUnchecked(props);",
      // A name that merely RESEMBLES the constructor. It was the
      // environment-backed constructor until phase 13 deleted it, and the
      // comment here used to say it was "a different count's business" — there
      // is no other count now, so what this row proves has changed rather than
      // gone. It proves the pattern is anchored on the constructor's whole name
      // and does not fire on a longer or differently-suffixed one that starts
      // the same way. The row is kept because that claim is still worth holding,
      // and because a call to a function that cannot exist is the cheapest
      // possible way to hold it.
      "const principal = principalFromEnv(env);",
    ]) {
      expect(fires(sample), `false-positived on ${sample}`).toBe(false);
    }
  });

  it("pins the known evasions as unseen, so nobody believes they are covered", () => {
    // Each of these DOES mint a principal. The docstring lists them. If the
    // pattern later starts to see one, this goes red: move the row out and
    // update the docstring.
    for (const sample of [
      // Re-bound to another name, by a renamed import or by a local.
      'import { principalFromProps as build } from "../principal";\nbuild(props);',
      "const build = principalFromProps;\nbuild(props);",
      // Reached as a computed member.
      'principalModule["principalFromProps"](props);',
      // A comment between the name and the parenthesis.
      "principalFromProps /* here */ (props);",
    ]) {
      expect(fires(sample), `now sees ${sample}`).toBe(false);
    }
  });

  it("carries no global flag, because scan() takes the first match with search()", () => {
    expect(PRINCIPAL_CONSTRUCTOR.flags).toBe("");
  });

  it("is wired into scan(): a tree with no owner file fails, once per owner", () => {
    // scripts/ is outside PRINCIPAL_CONSTRUCTOR_SCOPE, so scanning it alone
    // exercises the deleted direction against a real tree rather than a
    // synthetic list — and it must report BOTH owners, not one.
    const patterns = scan("scripts")
      .map((v) => v.pattern)
      .filter((p) => p === "principal-constructor-missing");
    expect(patterns).toEqual([
      "principal-constructor-missing",
      "principal-constructor-missing",
    ]);
  });

  it("passes on the real tree: exactly two minting sites, and they are the owners", () => {
    const patterns = scan().map((v) => v.pattern);
    expect(patterns).not.toContain("principal-constructor-missing");
    expect(patterns).not.toContain("principal-constructor-outside-owners");
  });
});

/** A module that does not exist, so nothing about the shipped tree can make the
 *  third arm agree by accident. */
const FABRICATED_MODULE = "src/dav/fabricated.ts";

/** The fabricated manifest, and the ONLY way the third arm is producible.
 *
 *  That arm compares the MANIFEST against the ALTERNATION. Both are module-level
 *  constants in the scanner, and every shipped guarded name is already in the
 *  shipped alternation — so on a clean tree no value of `collected` can produce
 *  it, and a rule nothing in the suite can ever observe is exactly the failure
 *  .claude/CLAUDE.md's Enforcement section names: a constraint whose arm can
 *  never fire looks identical to a constraint that was never added.
 *
 *  Only the HAND-WRITTEN side is substitutable. `davAlternationNames()` is
 *  called inside the checker and is not a parameter, so the measured side cannot
 *  be supplied by a test at all — which is what keeps this an injection point
 *  rather than a way to make the rule see less.
 *
 *  Three exports, tuned so one call produces exactly one of each arm. */
const FABRICATED_MANIFEST = {
  [FABRICATED_MODULE]: {
    why: "A fabricated module, declared only so the unguarded arm can be driven without editing the shipped rule.",
    exports: {
      // Guarded, and on the shipped alternation: no third-arm violation.
      getEvent: "guarded",
      // Guarded, and deliberately NOT on the shipped alternation: exactly one.
      createContactRecord: "guarded",
      // A reason rather than a disposition, so the alternation is not consulted
      // for it at all. Omitted from the collected list below, so it is the one
      // stale name.
      matchesNothing:
        "A matcher over a value the caller already holds. Issues no request.",
    },
  },
};

/** The collected list for that same module: the two guarded names, plus one name
 *  the fabricated manifest does not carry (one unmanifested), and omitting the
 *  reasoned name (one stale). */
const FABRICATED_COLLECTED = {
  [FABRICATED_MODULE]: ["getEvent", "createContactRecord", "unmanifestedHelper"],
};

describe("the DAV write modules are a manifested constraint", () => {
  // Pitfall 65, closed before the first v3.0 write entry point is written. A
  // name absent from the `dav-concurrent-request` alternation is invisible to
  // every assertion in this file — the rule-level set-equality guard included,
  // because that guard operates at the RULE level and cannot see inside one. So
  // today an unguarded entry point is indistinguishable from a guarded one by
  // any check that exists. This constraint inverts the failure direction: a new
  // export in a declared write module fails the scan until somebody records a
  // disposition for it.
  const CALENDAR_MODULE = "src/dav/calendar.ts";
  const CONTACTS_MODULE = "src/dav/contacts.ts";
  const DIAGNOSE_MODULE = "src/dav/diagnose.ts";

  /** What the walk collects for the declared modules, read off the SHIPPED tree
   *  through the scanner's own reader.
   *
   *  Never derived from the manifest. A collected list built from the manifest
   *  would agree with the manifest by construction, so dropping a name would
   *  drop it from both sides at once and every assertion here would stay green —
   *  the shape of dead gate this project has already shipped once and had to
   *  measure. */
  const shipped = (): Record<string, string[]> =>
    Object.fromEntries(
      Object.keys(DAV_WRITE_MODULES).map((path) => [
        path,
        exportedFunctionNames(rawSourceOf(path)),
      ]),
    );

  it("passes on the shipped tree: every export manifested, every guarded name in the alternation", () => {
    expect(Object.keys(DAV_WRITE_MODULES).sort()).toEqual([
      CALENDAR_MODULE,
      CONTACTS_MODULE,
      DIAGNOSE_MODULE,
    ]);
    expect(checkDavWriteCoverage(shipped())).toEqual([]);
  });

  it("reports the unmanifested arm, naming the module and the name, when a module gains an export", () => {
    // The realistic case and the whole reason this exists: a phase adds a write
    // to the contacts module, and nothing about writing that function makes
    // anybody think about the fan-out alternation.
    //
    // **This case named `createContact` until phase 16 shipped it**, which is
    // the constraint working rather than the case going stale: the name stopped
    // being a hypothetical unmanifested export the moment it acquired a real
    // disposition, and the arm it drives has to be driven by a name that is
    // genuinely absent from the manifest. `deleteContact` is the honest
    // replacement — contact delete is named OUT of scope by the roadmap, so
    // nothing is going to manifest it by accident, and it is also the next
    // contact write anybody will reach for.
    const collected = shipped();
    collected[CONTACTS_MODULE] = [...collected[CONTACTS_MODULE]!, "deleteContact"];
    const violations = checkDavWriteCoverage(collected);
    expect(violations.map((v) => v.pattern)).toEqual(["dav-write-export-unmanifested"]);
    expect(violations[0]!.file).toBe(CONTACTS_MODULE);
    expect(violations[0]!.why).toContain("deleteContact");
  });

  it("reports the stale arm, naming the module and the name, when a manifest name is no longer exported", () => {
    const collected = shipped();
    const dropped = collected[CALENDAR_MODULE]![0]!;
    collected[CALENDAR_MODULE] = collected[CALENDAR_MODULE]!.slice(1);
    const violations = checkDavWriteCoverage(collected);
    expect(violations.map((v) => v.pattern)).toEqual(["dav-write-manifest-stale"]);
    expect(violations[0]!.file).toBe(CALENDAR_MODULE);
    expect(violations[0]!.why).toContain(dropped);
  });

  it("reports the stale arm once per manifest name when a declared module was never walked", () => {
    // The deleted-module direction, and the reason this is a count rather than a
    // negative. A module that was moved, renamed or emptied is never walked, its
    // collected list is empty, and every manifest name comes back stale — a
    // manifest that matches nothing guards nothing, and that failure is quieter
    // than a duplicate because the tests covering the deleted code leave with it.
    //
    // It lives here rather than in either set-equality loop below on purpose:
    // those loops assert an exact violation COUNT, and one stale violation per
    // shipped manifest name would break their arithmetic. Here the count is the
    // point.
    const collected = shipped();
    delete collected[DIAGNOSE_MODULE];
    const violations = checkDavWriteCoverage(collected);
    const names = Object.keys(DAV_WRITE_MODULES[DIAGNOSE_MODULE]!.exports);
    expect(names.length).toBeGreaterThan(0);
    expect(violations.map((v) => v.pattern)).toEqual(
      names.map(() => "dav-write-manifest-stale"),
    );
    for (const violation of violations) expect(violation.file).toBe(DIAGNOSE_MODULE);
    expect(violations.map((v) => v.line)).toEqual(names.map(() => 0));
    expect(violations.map((v) => v.column)).toEqual(names.map(() => 0));
  });

  it("reports the unguarded arm when a guarded manifest name is absent from the alternation", () => {
    // Driven through the checker's SECOND parameter, never by editing the
    // shipped rule and never by substituting the alternation — which the checker
    // does not accept as a parameter, precisely so that it cannot be done.
    const violations = checkDavWriteCoverage(
      { [FABRICATED_MODULE]: ["getEvent", "createContactRecord", "matchesNothing"] },
      FABRICATED_MANIFEST,
    );
    expect(violations.map((v) => v.pattern)).toEqual(["dav-write-entry-point-unguarded"]);
    expect(violations[0]!.file).toBe(FABRICATED_MODULE);
    // Named in the reason, so a checker producing this arm for some OTHER reason
    // still fails here.
    expect(violations[0]!.why).toContain("createContactRecord");
    expect(violations[0]!.why).not.toContain("getEvent");
  });

  it("still measures the SHIPPED alternation when driven from a fabricated manifest", () => {
    // The guard on the guard above. `getEvent` is in the shipped alternation and
    // `createContactRecord` is not, and the fabricated manifest marks both
    // guarded — so if a test could supply the alternation, both or neither would
    // fire. Exactly one does, which is only true if the checker read the rule
    // that actually ships.
    const names = davAlternationNames();
    expect(names).toContain("getEvent");
    expect(names).not.toContain("createContactRecord");
  });

  it("takes the manifest as an OPTIONAL parameter, so a one-argument call is the ordinary call", () => {
    // A default parameter does not count toward a function's arity, so this is
    // mechanical proof that the shipped constant is the default.
    expect(checkDavWriteCoverage.length).toBe(1);
    const collected = shipped();
    expect(checkDavWriteCoverage(collected)).toEqual(
      checkDavWriteCoverage(collected, DAV_WRITE_MODULES),
    );
  });

  it("keeps the manifest parameter an injection point rather than a back door", () => {
    // Three assertions, and each closes a different route.
    //
    // FIRST, arity. A default parameter does not count toward a function's
    // arity, so `length === 1` is mechanical proof that the shipped constant is
    // the default and a one-argument call is the ordinary call.
    expect(checkDavWriteCoverage.length).toBe(1);

    const stripped = rawSourceOf(SCANNER_PATH)
      // Block comments and line comments both, so a docstring naming the checker
      // cannot be mistaken for a call to it.
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "");

    // SECOND, the production call site's argument list, byte-exactly. Collected
    // with a lookbehind that excludes `function `, so the declaration is not
    // counted as a call.
    //
    // "One argument, no comma" was NOT enough, and that is the whole reason this
    // assertion reads the identifier: `checkDavWriteCoverage(somethingNarrowed)`
    // has one argument and no comma, so the weaker form passes while narrowing
    // what the rule is shown — the one harm this parameter could do. Pinning the
    // IDENTIFIER closes it. The call cannot take a filter, a derived copy or a
    // literal, and with arity 1 it cannot take a manifest at all.
    const calls = [
      ...stripped.matchAll(/(?<!function\s)\bcheckDavWriteCoverage\s*\(([^)]*)\)/g),
    ];
    expect(calls.length, "the sole invocation outside the declaration").toBe(1);
    expect(calls[0]![1]).toBe("davWriteExports");

    // THIRD, the accumulator itself. `const` closes reassignment at the language
    // level; the occurrence count closes in-place filtering, because a `delete`
    // or a reassignment would be a fourth occurrence. The three are the
    // declaration, the collection block's assignment from the export reader, and
    // the call above.
    expect(/\bconst\s+davWriteExports\s*=/.test(stripped)).toBe(true);
    expect(
      /davWriteExports\[[A-Za-z]+\]\s*=\s*exportedFunctionNames\(contents\)/.test(stripped),
    ).toBe(true);
    expect([...stripped.matchAll(/\bdavWriteExports\b/g)].length).toBe(3);

    // Two things worth saying rather than leaving implied.
    //
    // The ALTERNATION is deliberately not a parameter of the checker, so the
    // MEASURED side of the unguarded arm cannot be substituted at all — there is
    // nowhere to feed a convenient alternation, which is what makes the manifest
    // parameter an injection point rather than a way to make the rule see less.
    //
    // And where this assertion STOPS. It reads the shipped call site's TEXT, so
    // it cannot see a narrowing performed inside `exportedFunctionNames`, and it
    // cannot see a declared module added to the scanner's exclusion set. The
    // first is held by the export-reader assertions against shipped source above;
    // the second is loud rather than quiet, because an unwalked module's manifest
    // names all come back as the stale arm. .claude/CLAUDE.md is explicit both
    // that a rule is never made to see less and that a rule believed to prove
    // more than it does is worse than one whose limits are written down — this
    // does both halves.
    //
    // If the comment strip ever over-reaches — a string in the scanner carrying
    // an unbalanced comment opener would swallow real code — the call site
    // disappears from the stripped text and this goes RED. It fails closed,
    // which is the correct direction for a gate.
  });

  it("is wired into scan(): a tree with no declared module fails, once per manifest name", () => {
    // scripts/ holds none of the declared modules, so scanning it in isolation
    // exercises the deleted direction against a real tree rather than a synthetic
    // map. This proves the WIRING rather than the function — the four wiring
    // points are where a count constraint half-lands.
    const inIsolation = scan("scripts").map((v) => v.pattern);
    const staleCount = inIsolation.filter((p) => p === "dav-write-manifest-stale").length;
    const manifested = Object.values(DAV_WRITE_MODULES).reduce(
      (total, entry) => total + Object.keys(entry.exports).length,
      0,
    );
    expect(staleCount).toBe(manifested);

    const whole = scan().map((v) => v.pattern);
    expect(whole).not.toContain("dav-write-manifest-stale");
    expect(whole).not.toContain("dav-write-export-unmanifested");
    expect(whole).not.toContain("dav-write-entry-point-unguarded");
  });

  it("gives the three ids distinct sort keys, straight after the principal constructor count's", () => {
    // Read by RUNNING the checker, never by reading the source. The fabricated
    // manifest is what makes one call produce all three.
    const violations = checkDavWriteCoverage(FABRICATED_COLLECTED, FABRICATED_MANIFEST);
    const keyOf = (pattern: string) =>
      violations.find((v) => v.pattern === pattern)!.patternIndex;
    expect(keyOf("dav-write-export-unmanifested")).toBe(FORBIDDEN.length + 18);
    expect(keyOf("dav-write-manifest-stale")).toBe(FORBIDDEN.length + 19);
    expect(keyOf("dav-write-entry-point-unguarded")).toBe(FORBIDDEN.length + 20);
  });

  it("carries no shared regex state: a second call over the same contents returns the same names", () => {
    // The reader needs `matchAll`, which a pattern without the global flag
    // refuses outright — so unlike every other constraint pattern in the scanner
    // it cannot simply drop the flag. The pattern is constructed fresh per call
    // instead, and this is what a carried `lastIndex` would break: the second
    // call would start part-way through the file and come back short.
    const sample = "export function first() {}\nexport async function second() {}\n";
    expect(exportedFunctionNames(sample)).toEqual(["first", "second"]);
    expect(exportedFunctionNames(sample)).toEqual(["first", "second"]);
    const shippedText = rawSourceOf(CALENDAR_MODULE);
    expect(exportedFunctionNames(shippedText)).toEqual(exportedFunctionNames(shippedText));
    // Source order, not sorted, because the manifest is read in declaration order.
    expect(exportedFunctionNames(shippedText)[0]).toBe("listCalendars");
  });

  it("pins the known evasions as unseen, so nobody believes they are covered", () => {
    // Each of these DOES add an export, and the reader sees none of them. This is
    // a limit written down rather than a gap being tolerated: the manifest's own
    // docstring lists all four, and if the reader later starts to see one, this
    // goes red — move the row out and update the docstring.
    for (const sample of [
      // A re-export. No `function` keyword follows the `export`.
      'export { getEvent } from "./elsewhere";',
      // A `const` arrow export. The one most likely to arrive by accident,
      // because it is a style choice rather than an evasion.
      "export const getEvent = async (env) => {};",
      // A name bound and exported separately: the two words are never adjacent.
      "function getEvent() {}\nexport { getEvent };",
      // A module-local fan-out entry point, which an export list cannot see at
      // all. The two real ones are named in the manifest's docstring.
      "async function collectFrom(env, collection) {}",
    ]) {
      expect(exportedFunctionNames(sample), `now sees ${sample}`).toEqual([]);
    }
  });

  it("compares export names by exact ASCII equality, in both directions at once", () => {
    // No case folding, no Unicode normalisation, no trimming. A name differing
    // from a manifest entry only by case is two different names, and the correct
    // answer is BOTH arms in one run: the export the module actually ships is one
    // nobody decided about, and the name the manifest lists is not there.
    const caseManifest = {
      [FABRICATED_MODULE]: {
        why: "A fabricated module, declared only to drive the exact-equality assertion.",
        exports: { getEvent: "guarded" },
      },
    };
    const violations = checkDavWriteCoverage(
      { [FABRICATED_MODULE]: ["GetEvent"] },
      caseManifest,
    );
    expect(violations.map((v) => v.pattern)).toEqual([
      "dav-write-export-unmanifested",
      "dav-write-manifest-stale",
    ]);
    expect(violations[0]!.why).toContain("GetEvent");
    expect(violations[0]!.why).not.toContain(" getEvent");
    expect(violations[1]!.why).toContain("getEvent");
  });

  it("pins the prefix-shadow exact list for the manifest's guarded names", () => {
    // The same defect the alternation's own block records, asked of the manifest:
    // the alternation carries no leading word boundary, so a guarded name that
    // CONTAINS another entry is matched through that other entry. `getEventWithEtag`
    // is exactly that — `getEvent` precedes it and is a prefix of it — and it is
    // recorded as an EXACT LIST rather than tolerated, so a write export added
    // later with the same defect fails here and has to be argued for.
    //
    // The repair is forbidden: a trailing word boundary on the group would make
    // the safety rule match strictly LESS than it does today.
    const names = davAlternationNames();
    const guarded = Object.values(DAV_WRITE_MODULES).flatMap((entry) =>
      Object.entries(entry.exports)
        .filter(([, disposition]) => disposition === "guarded")
        .map(([name]) => name),
    );
    expect(guarded.length, "the guarded set came back empty").toBeGreaterThan(10);
    const covered = guarded.filter((name) =>
      names.some((other) => other !== name && name.includes(other)),
    );
    // `getContactWithEtag` (CONW-02) is the second, and it is the same defect on
    // the other tree: `getContact` is a guarded manifest name in the same module
    // and is a prefix of it. Argued for in the alternation's own block above rather
    // than argued twice; recorded here because this list is what a write export
    // added later has to pass.
    expect(
      covered,
      "a guarded manifest name is matched through another alternation entry, so its coverage claim cannot fail",
    ).toEqual(["getEventWithEtag", "getContactWithEtag"]);
  });

  it("is deterministic: two runs over the same input return deeply equal arrays", () => {
    // `scan()` sorts by file, line, column then rule index, and every violation
    // this checker emits for one module shares all four — so the checker's own
    // emission order is what makes the output byte-identical between runs.
    const collected = shipped();
    collected[CALENDAR_MODULE] = [...collected[CALENDAR_MODULE]!.slice(2), "somethingNew"];
    const first = checkDavWriteCoverage(collected);
    const second = checkDavWriteCoverage(collected);
    expect(first.length).toBeGreaterThan(0);
    expect(first).toEqual(second);
    expect(checkDavWriteCoverage(FABRICATED_COLLECTED, FABRICATED_MANIFEST)).toEqual(
      checkDavWriteCoverage(FABRICATED_COLLECTED, FABRICATED_MANIFEST),
    );
  });
});

describe("one function composes the human-facing line (CONF-04)", () => {
  const owner = { file: CONFIRM_LINE_OWNER, line: 1108, column: 17 };
  // The realistic second site, and realistic rather than hypothetical: the tool
  // layer is where "just phrase it from here" gets written, because that is the
  // layer holding the response the sentence rides in.
  const elsewhere = { file: "src/mcp/tools/calendar.ts", line: 1755, column: 23 };

  /** A fresh copy per probe, so no state can carry between samples. */
  const fires = (sample: string): boolean =>
    new RegExp(CONFIRM_LINE_COMPOSER.source, CONFIRM_LINE_COMPOSER.flags).test(
      sample,
    );

  it("passes when the confirm module is the only file that defines the composer", () => {
    expect(checkConfirmLineOwnership([owner])).toEqual([]);
  });

  it("reports a violation naming the second file when another module defines one", () => {
    const violations = checkConfirmLineOwnership([owner, elsewhere]);
    expect(violations.map((v) => v.pattern)).toEqual([
      "confirm-line-composer-duplicated",
    ]);
    expect(violations[0]!.file).toBe(elsewhere.file);
    expect(violations[0]!.line).toBe(elsewhere.line);
    expect(violations[0]!.column).toBe(elsewhere.column);
  });

  it("reports the SECOND definition inside the owner file, which used to pass", () => {
    // The gap this closes. While the collector used `String.prototype.search` a
    // file contributed at most one entry, so two composers both defined in
    // src/confirm.ts produced ONE entry, that entry was the owner, and the
    // checker skipped it. "One composer, at one definition site" was then false
    // with the scan green. The collector now counts every match in a file.
    const second = { file: CONFIRM_LINE_OWNER, line: 1402, column: 9 };
    const violations = checkConfirmLineOwnership([owner, second]);

    expect(violations.map((v) => v.pattern)).toEqual([
      "confirm-line-composer-duplicated",
    ]);
    // The SECOND one is named, not the first: the first is the composer.
    expect(violations[0]!.line).toBe(second.line);
    expect(violations[0]!.column).toBe(second.column);
    // And the reason the hook prints says an in-owner duplicate counts, because
    // a reader who saw only "a second module" would read this as a false alarm.
    expect(violations[0]!.why).toContain(CONFIRM_LINE_OWNER);
  });

  it("stays global-safe across files: a second file's definition is still found", () => {
    // The collector builds its global copy fresh per file. A shared one would
    // carry `lastIndex` between files, so the composer in the SECOND file
    // scanned would be searched from an offset past it and silently missed --
    // the duplicated arm would then stop firing on exactly the shape it exists
    // for. Driven through the exported constant, which must stay flagless.
    expect(CONFIRM_LINE_COMPOSER.global).toBe(false);
    const fresh = () => new RegExp(CONFIRM_LINE_COMPOSER, "g");
    const two = [
      "function composeConfirmationLine(a, b) {}",
      "function composeConfirmationLine(c, d) {}",
    ];
    for (const contents of two) {
      expect([...contents.matchAll(fresh())]).toHaveLength(1);
    }
    // And two in ONE file are two, which is what `search()` could not see.
    expect([...two.join("\n").matchAll(fresh())]).toHaveLength(2);
  });

  it("reports a violation naming the owner when nothing defines one", () => {
    // The direction a negative cannot see, and the one that matters most here:
    // a composer deleted, renamed or inlined guards nothing, and nothing goes
    // red on the way out because the tests covering it leave with it. Five
    // later phases inherit this sentence; losing it is quieter than duplicating
    // it.
    const violations = checkConfirmLineOwnership([]);
    expect(violations.map((v) => v.pattern)).toEqual([
      "confirm-line-composer-missing",
    ]);
    expect(violations[0]!.file).toBe(CONFIRM_LINE_OWNER);
    expect(violations[0]!.line).toBe(0);
    expect(violations[0]!.column).toBe(0);
  });

  it("names the one owner, and collects from the source tree only", () => {
    expect(CONFIRM_LINE_OWNER).toBe("src/confirm.ts");
    expect(CONFIRM_LINE_SCOPE).toBe("src/");
  });

  it("matches the shipped definition, on one line and split across several", () => {
    for (const sample of [
      // src/confirm.ts as it is written today.
      "export function composeConfirmationLine(",
      // The same after a formatter breaks the signature up.
      "export function composeConfirmationLine(\n  summary: ConfirmationSummary,\n): string {",
      // Unexported, which is still a definition.
      "function composeConfirmationLine(summary, tense) {",
      // The declaration keyword and the name on separate lines.
      "function\n  composeConfirmationLine(summary, tense) {",
    ]) {
      expect(fires(sample), `missed ${sample}`).toBe(true);
    }
  });

  it("does not see a CALL or an IMPORT, only a definition", () => {
    // These are the rows a pattern anchored on the bare NAME would catch, and
    // catching them would be fatal rather than untidy: every call site lives
    // under the collected scope, so the rule would report the very sites it
    // exists to protect and the pre-commit hook would refuse every commit in
    // the repository.
    for (const sample of [
      'const line = composeConfirmationLine(summary, "would");',
      "    confirmationLine: composeConfirmationLine(summary, tense),",
      'import { composeConfirmationLine } from "../../confirm";',
      "  composeConfirmationLine,",
      // A mention in prose with no declaration keyword in front of it.
      " * See `composeConfirmationLine`, which owns the argument.",
    ]) {
      expect(fires(sample), `now sees ${sample}`).toBe(false);
    }
  });

  it("pins the known evasions as unseen, so nobody believes they are covered", () => {
    // Each of these DOES produce a second human-facing sentence. The constant's
    // docstring lists them and names what actually holds them instead -- the
    // byte-exact line table in test/confirm.test.ts and the fence audit's
    // key-set comparison. If the pattern later starts to see one, this goes
    // red: move the row out and update the docstring.
    for (const sample of [
      // 1. a second composer bound to a const arrow rather than declared
      "export const composeConfirmationLine = (summary, tense) => `${tense}`;",
      // 2. a line assembled inline at a tool shaper as a template literal
      "  const line = `Deleting event '${title}'. This cannot be undone.`;",
      // 3. a re-export under an alias
      'export { composeConfirmationLine as composeLine } from "../../confirm";',
      // 4. a helper that rewrites the composed line before it reaches the
      //    response
      "function tighten(line) {\n  return line.replace(/ in it/, '');\n}",
    ]) {
      expect(fires(sample), `now sees ${sample}`).toBe(false);
    }
  });

  it("carries no global flag, because the collector builds its own copy per file", () => {
    // The flag has to be OFF on the shared export. `lastIndex` lives on the
    // regex object, so a global constant reused across files would search the
    // next file from wherever the previous one left off.
    expect(CONFIRM_LINE_COMPOSER.flags).toBe("");
  });

  it("gives the two ids distinct sort keys, straight after the write-coverage count's", () => {
    // Read off violations the checker PRODUCED rather than off the source, so
    // an id renamed in one place and not the other cannot pass here.
    const violations = [
      ...checkConfirmLineOwnership([owner, elsewhere]),
      ...checkConfirmLineOwnership([]),
    ];
    const duplicated = violations.find(
      (v) => v.pattern === "confirm-line-composer-duplicated",
    )!;
    const missing = violations.find(
      (v) => v.pattern === "confirm-line-composer-missing",
    )!;

    expect(duplicated.patternIndex).toBe(FORBIDDEN.length + 21);
    expect(missing.patternIndex).toBe(FORBIDDEN.length + 22);
  });

  it("is wired into scan(): a tree with no composer reports the owner as missing", () => {
    // scripts/ is outside CONFIRM_LINE_SCOPE, so scanning it alone exercises
    // the deleted direction against a real tree rather than a synthetic list.
    expect(scan("scripts").map((v) => v.pattern)).toContain(
      "confirm-line-composer-missing",
    );
  });

  it("passes on the real tree: exactly one definition, and it is the owner", () => {
    const patterns = scan().map((v) => v.pattern);
    expect(patterns).not.toContain("confirm-line-composer-missing");
    expect(patterns).not.toContain("confirm-line-composer-duplicated");
  });
});

describe("the count constraints as a set", () => {
  /** One entry per password owner, in the owners' own order. */
  const bothPasswordOwners = PASSWORD_READER_OWNERS.map((file) => ({ file, line: 1, column: 1 }));

  /** The same, for the second two-owner count. */
  const bothConstructorOwners = PRINCIPAL_CONSTRUCTOR_OWNERS.map((file) => ({
    file,
    line: 1,
    column: 1,
  }));

  it("covers every ownership violation id with an exercised sample, in both directions", () => {
    // The parallel of the rule-id set-equality assertion above, and it exists
    // for the same reason: a count constraint that can never emit one of its
    // two ids is indistinguishable from one that was never added. Every id is
    // produced by actually running a checker, never restated as a literal.
    const nonOwner = { file: "src/dav/calendar.ts", line: 1, column: 1 };
    const observed = new Set<string>([
      ...checkSocketOwnership([
        { file: SOCKET_OWNER, line: 1, column: 1 },
        { file: "src/mail/imap-session.ts", line: 1, column: 1 },
      ]).map((v) => v.pattern),
      ...checkSocketOwnership([]).map((v) => v.pattern),
      ...checkDavHostOwnership([nonOwner]).map((v) => v.pattern),
      ...checkDavHostOwnership([]).map((v) => v.pattern),
      ...checkDavFetchOwnership([nonOwner]).map((v) => v.pattern),
      ...checkDavFetchOwnership([]).map((v) => v.pattern),
      ...checkAppendOwnership([nonOwner]).map((v) => v.pattern),
      ...checkAppendOwnership([]).map((v) => v.pattern),
      ...checkSubscriptionFeedFetchOwnership([nonOwner]).map((v) => v.pattern),
      ...checkSubscriptionFeedFetchOwnership([]).map((v) => v.pattern),
      ...checkPropsReaderOwnership([nonOwner]).map((v) => v.pattern),
      ...checkPropsReaderOwnership([]).map((v) => v.pattern),
      // Two owners: a non-owner beside both, then one owner missing.
      ...checkPasswordReaderOwnership([...bothPasswordOwners, nonOwner]).map((v) => v.pattern),
      ...checkPasswordReaderOwnership(bothPasswordOwners.slice(0, 1)).map((v) => v.pattern),
      // One owner, so the same two lists the props count is fed.
      // One owner again, so the same pair once more.
      ...checkAddressHashOwnership([nonOwner]).map((v) => v.pattern),
      ...checkAddressHashOwnership([]).map((v) => v.pattern),
      // One owner, so the same two lists once more.
      ...checkConfirmLineOwnership([nonOwner]).map((v) => v.pattern),
      ...checkConfirmLineOwnership([]).map((v) => v.pattern),
      // The second two-owner count, fed the same pair of lists the password
      // count is fed and for the same reason.
      ...checkPrincipalConstructorOwnership([
        ...bothConstructorOwners,
        nonOwner,
      ]).map((v) => v.pattern),
      ...checkPrincipalConstructorOwnership(
        bothConstructorOwners.slice(0, 1),
      ).map((v) => v.pattern),
      // The write-module constraint, fed ONE call carrying a FABRICATED manifest
      // rather than the two lists every count above is fed. Three reasons it is
      // shaped differently, and all three are properties of the constraint rather
      // than conveniences: it takes a MAP rather than a list of matches; its three
      // arms can all be produced by a single well-chosen call; and its third arm
      // cannot be produced from the shipped manifest at all, because every shipped
      // guarded name is already in the shipped alternation.
      //
      // Tuned to produce exactly one of each arm, so the count loop below can feed
      // it the same single call. The empty-map direction is deliberately NOT here:
      // it yields one stale violation per shipped manifest name, which would break
      // that loop's arithmetic. It has its own `it` above, where the count is the
      // point.
      ...checkDavWriteCoverage(FABRICATED_COLLECTED, FABRICATED_MANIFEST).map(
        (v) => v.pattern,
      ),
    ]);
    expect([...observed].sort()).toEqual([...OWNERSHIP_VIOLATION_IDS].sort());
  });

  it("gives every count constraint a reason a rejected commit can act on", () => {
    const nonOwner = { file: "src/dav/calendar.ts", line: 1, column: 1 };
    const violations = [
      ...checkSocketOwnership([nonOwner]),
      ...checkSocketOwnership([]),
      ...checkDavHostOwnership([nonOwner]),
      ...checkDavHostOwnership([]),
      ...checkDavFetchOwnership([nonOwner]),
      ...checkDavFetchOwnership([]),
      ...checkAppendOwnership([nonOwner]),
      ...checkAppendOwnership([]),
      ...checkSubscriptionFeedFetchOwnership([nonOwner]),
      ...checkSubscriptionFeedFetchOwnership([]),
      ...checkPropsReaderOwnership([nonOwner]),
      ...checkPropsReaderOwnership([]),
      // The password count has TWO owners, so it cannot be fed the same pair
      // of lists. A lone non-owner would give one outside AND two missing, and
      // an empty list would give two missing. Both owners plus a non-owner is
      // exactly one outside; one owner alone is exactly one missing.
      ...checkPasswordReaderOwnership([...bothPasswordOwners, nonOwner]),
      ...checkPasswordReaderOwnership(bothPasswordOwners.slice(0, 1)),
      // One owner, so a lone non-owner and an empty list give one of each.
      // Same again for the one address-hashing producer.
      ...checkAddressHashOwnership([nonOwner]),
      ...checkAddressHashOwnership([]),
      // One owner again, so a lone non-owner and an empty list give one of each.
      ...checkConfirmLineOwnership([nonOwner]),
      ...checkConfirmLineOwnership([]),
      // TWO owners again, so the same asymmetric pair the password count needs:
      // both owners plus a non-owner is exactly one outside, and one owner
      // alone is exactly one missing.
      ...checkPrincipalConstructorOwnership([
        ...bothConstructorOwners,
        nonOwner,
      ]),
      ...checkPrincipalConstructorOwnership(bothConstructorOwners.slice(0, 1)),
      // The same single fabricated call the loop above is fed, for the same three
      // reasons, and tuned to contribute exactly three violations — one per arm —
      // so this loop's arithmetic still reads one violation per id.
      ...checkDavWriteCoverage(FABRICATED_COLLECTED, FABRICATED_MANIFEST),
    ];
    expect(violations.length).toBe(OWNERSHIP_VIOLATION_IDS.length);
    for (const violation of violations) {
      expect(violation.why.length, `${violation.pattern} has a label, not a reason`)
        .toBeGreaterThan(80);
    }
  });

  it("keeps the discovery module inside every pattern rule's reach", () => {
    // The whole point of expressing the hostname rule as a count: EXCLUDED
    // skips a file for EVERY rule, so buying the hostname exemption with a path
    // exclusion would have dropped the logging, fan-out and date rules on the
    // one module that most needs them.
    expect(EXCLUDED.has(DAV_HOST_OWNER)).toBe(false);
    expect(EXCLUDED.has(DAV_FETCH_OWNER)).toBe(false);
    // The same argument for the write, where it bites hardest: the module
    // holding the write is the module that most needs the logging ban, the
    // session fan-out ban and the peeking-fetch ban.
    expect(EXCLUDED.has(APPEND_OWNER)).toBe(false);
    // And for the subscription-feed fetcher: it is the one module in the
    // repository handed a stranger-supplied third-party URL, so it is also the
    // one that most needs the logging ban applying to it in full.
    expect(EXCLUDED.has(SUBSCRIPTION_FEED_FETCH_OWNER)).toBe(false);
    // And for the door: it is the one module that holds the grant's props, so
    // it is the one that most needs the props-in-log rule applying to it.
    expect(EXCLUDED.has(PROPS_READER_OWNER)).toBe(false);
    // And for both minting sites. These two are the files that hold a live
    // credential longest — the door holds a decrypted grant, the login page
    // holds a value somebody just typed — so they are the two that most need
    // the logging ban applying to them in full. Buying either a count
    // exemption with a path exclusion would drop that ban at the same time,
    // which is the whole reason these are counts rather than exclusions.
    for (const owner of PRINCIPAL_CONSTRUCTOR_OWNERS) {
      expect(EXCLUDED.has(owner), `${owner} is excluded by path`).toBe(false);
    }
    const logging = FORBIDDEN.find((r) => r.id === "logging-anywhere-under-src")!;
    expect(
      matchRule(logging, 0, DAV_HOST_OWNER, 'console.log("resolved", homeUrl);').length,
    ).toBeGreaterThan(0);
  });
});

describe("the commit-time gate", () => {
  it("exists, is executable, and still runs both of its checks", () => {
    // That it *blocks* a commit cannot be asserted from inside the repository
    // without side effects; that was verified once by hand and recorded in
    // 01-04-SUMMARY.md.
    expect(checkCommitHook().map(formatViolation)).toEqual([]);
  });

  it("reports the gate as missing when it is not there", () => {
    const violations = checkCommitHook(".husky/pre-commit-that-does-not-exist");
    expect(violations.map((v) => v.pattern)).toEqual(["commit-gate-missing"]);
  });

  it("reports a hook body that does not abort on error", () => {
    // Pointed at a real file that exists, is readable, and is definitively not
    // a shell script, so the check is exercised against contents rather than
    // against an absence. A fixture with every other property satisfied would
    // have to be a file carrying a deliberately-broken copy of the gate, which
    // is not worth committing to the repository to sharpen one assertion.
    //
    // The abort line is the one thing standing between a printed violation and
    // a successful commit; without it the scan is advisory.
    const patterns = checkCommitHook("package.json").map((v) => v.pattern);
    expect(patterns).toContain("commit-gate-no-set-e");
    expect(patterns).not.toContain("commit-gate-missing");
  });
});
