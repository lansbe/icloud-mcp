// Pure iCalendar parsing: inline-timezone registration, client-side recurrence
// expansion, and the timezone reading CAL-03 turns on.
//
// A string goes in and plain objects come out. No environment, no fetch, no
// import from the transport, and nothing from `src/mail/` in either direction —
// the same shape `src/mail/imap-parser.ts` and `src/mail/mime.ts` keep one tree
// over. That is what lets CAL-02 and CAL-03 be tested at all under D-09's rule
// that no automated job may authenticate against the real Apple ID: the whole
// surface unit-tests against literal fixture strings with nothing stood up.
//
// **Both halves of this module fail SILENTLY when they fail, which is why it is
// separated from the service layer that calls it.** An unresolved timezone does
// not throw — the time becomes floating, one accessor then reads it as UTC and
// another reads it in the host machine's zone, and the vitest pool inherits the
// host's zone while production Workers run UTC. An occurrence someone moved
// does not throw either — it quietly reports its original time and its original
// summary unless every exception is related to the master BEFORE iteration.
// Neither is caught by a fixture with one component and a comfortably-interior
// date range, so both have fixtures shaped against them in
// `test/fixtures/dav-bytes.ts`.
//
// **Everything this module returns from a resource is UNTRUSTED CONTENT, and it
// is returned VERBATIM.** A summary, description, location, organiser name and
// attendee name are all chosen by whoever put the event on the calendar, which
// for a personal assistant reading a real account means anyone who can send an
// invitation. Framing that text as content rather than instruction is the job of
// `src/mcp/untrusted.ts` at the tool boundary, and it is deliberately NOT
// attempted here (T-03-18): stripping or "cleaning" in the parser would be a
// second mitigation of the same threat, drifting away from the first, which is
// exactly what D-56 rejects. Nothing below trims, escapes, or rewrites a value.
//
// The design set is selected automatically from the resource's own VERSION
// property; nothing here needs to be told which iCalendar version it is reading.
//
// This module contains no logging calls of any kind and must never acquire any.

import ICAL from "ical.js";
import { DavConnectError } from "./errors";

/**
 * ical.js is ESM with a DEFAULT EXPORT ONLY.
 *
 * `import { Event } from "ical.js"` does not resolve — the package exports one
 * namespace object and nothing else. These aliases exist so the library's types
 * can be named in signatures without a named import that would not link.
 */
type IcalComponent = InstanceType<typeof ICAL.Component>;
type IcalTime = InstanceType<typeof ICAL.Time>;
type IcalTimezone = InstanceType<typeof ICAL.Timezone>;
type IcalProperty = InstanceType<typeof ICAL.Property>;
type IcalEvent = InstanceType<typeof ICAL.Event>;
type OccurrenceDetails = ReturnType<IcalEvent["getOccurrenceDetails"]>;

/**
 * The zone identifier a time carries when it is anchored to nothing.
 *
 * Read off the library rather than written as a literal, because it is the
 * library's own sentinel and the whole unresolved-timezone detection below
 * turns on recognising it. A literal that drifted out of step with the library
 * would not fail — it would simply stop detecting, which is the failure mode
 * this module exists to prevent.
 */
const FLOATING_TZID = ICAL.Timezone.localTimezone.tzid;

/**
 * The ceiling on occurrences one expansion may return.
 *
 * It exists because iteration is range-start-INDEPENDENT: the iterator begins
 * at the series' own start rather than at the range the caller asked about, so
 * a daily event begun a decade ago costs thousands of steps to reach a current
 * range, and a long range over a frequent rule produces a correspondingly long
 * answer. This bounds the answer.
 *
 * Two thousand occurrences is far above any range a person asks a personal
 * assistant about — a daily event over a full year is 365 — and far below
 * anything that threatens the isolate's heap or its CPU budget.
 *
 * On trip it TRUNCATES and sets `truncated`. It never raises, and it never
 * invents a fifth error category: the flag is this server's own statement about
 * what it did, on exactly the footing `hasMore` and `unsupportedCharset`
 * already sit on, which is why plan 03-06 puts it in the TRUSTED half of the
 * response.
 */
export const MAX_EXPANDED_OCCURRENCES = 2000;

/**
 * The ceiling on iterator steps one expansion may take.
 *
 * **A second cap, because the first one cannot see the failure it guards.**
 * `MAX_EXPANDED_OCCURRENCES` counts what lands IN the requested range; the
 * steps a rule spends walking from its own start up to that range are skipped,
 * not counted. A `FREQ=SECONDLY` rule beginning a decade before the range —
 * legal iCalendar, and authored by whoever sent the invitation — therefore
 * burns hundreds of millions of steps while the occurrence count sits at zero,
 * and the occurrence cap never trips (T-03-15).
 *
 * Quarter of a million steps clears every legitimate shape by a wide margin: a
 * daily event running since 2000 reaches a 2026 range in about nine and a half
 * thousand, an hourly one in about two hundred thousand. A rule that cannot
 * reach the range inside that is not a calendar entry anyone keeps.
 *
 * Same disposition as the occurrence cap on trip: truncate and report, never
 * raise. The caller asked a question that has a partial answer, and a partial
 * answer labelled as partial is more useful than an error.
 */
export const MAX_ITERATOR_STEPS = 250_000;

/**
 * The ceiling on iterator steps ONE LISTING may take, across every resource.
 *
 * **A third cap, because the second one is per resource and resets** (03-REVIEW
 * WR-01). T-03-15 and T-03-32 record an occurrence cap that "terminates it
 * regardless", and `MAX_ITERATOR_STEPS` does terminate any ONE rule. What
 * neither cap bounded was the product: a page walks every object every calendar
 * returned in range, each gets a fresh quarter-million-step allowance, and the
 * worst case is therefore `resources × 250,000` with no ceiling at all. That is
 * not a slow answer, it is no answer — the isolate is killed mid-request, and
 * the caller gets neither the rows nor the `truncated` flag that exists to say
 * the answer is partial. Every other cap in this file fails by TELLING the
 * caller; this axis failed by disappearing.
 *
 * The number is measured rather than guessed. A step costs about three
 * microseconds in this runtime (250,000 of them take roughly three quarters of
 * a second), so a million steps is about three seconds of CPU — a tenth of the
 * paid plan's thirty-second budget, leaving the parse, the sort, the identifier
 * minting and a listing's three round trips their share of what is left. That
 * figure was nineteen while a listing could sweep the whole account; the
 * account-wide form was withdrawn, which widens this margin rather than
 * narrowing it, so the number below stays where it was measured. The old worst
 * case, at two hundred in-range resources, is fifty
 * million steps: about two and a half minutes, and dead long before that.
 *
 * A million is also far above any legitimate listing. The most expensive real
 * shape is a long-running recurring series, and the figures above put a daily
 * event running since 2000 at about nine and a half thousand steps — so a
 * hundred of them, all still running, all overlapping one range, still fits. An
 * account that does not fit is truncated and told so, which is the same
 * disposition the other two caps already have.
 *
 * **Both ceilings hold at once.** The per-resource cap is what stops one
 * pathological rule eating the whole page's allowance and starving every
 * resource behind it; this one is what stops a thousand well-behaved rules
 * adding up to a dead isolate. `expandWithinBudget` applies the smaller of the
 * two, which is the only combination in which neither is decorative.
 */
export const MAX_LISTING_ITERATOR_STEPS = 1_000_000;

/**
 * An iterator-step allowance shared across the resources of one listing.
 *
 * Mutable and passed by reference on purpose: a shared budget IS shared state,
 * and modelling it as anything else would mean threading a running total back
 * out through every return value and trusting each call site to add it up. The
 * object is created per page and never outlives the request.
 */
export interface StepBudget {
  /** Steps still available to this listing. Never negative. */
  remaining: number;
}

/** A fresh allowance for one listing. The total is a parameter so a test can
 *  exercise exhaustion without spending three seconds of real CPU reaching it. */
export function newStepBudget(
  total: number = MAX_LISTING_ITERATOR_STEPS,
): StepBudget {
  return { remaining: total };
}

/**
 * Expand one resource against a listing-wide allowance, and spend what it cost.
 *
 * The whole of WR-01's fix, in one place rather than at each call site, because
 * the two things that make it correct are both easy to get wrong and neither
 * fails loudly:
 *
 *   - The allowance handed to the expansion is the SMALLER of the per-resource
 *     cap and what is left. Passing the remaining budget alone would let the
 *     first pathological rule spend the entire page's allowance; passing the
 *     per-resource cap alone is exactly the bug being fixed.
 *   - An exhausted budget returns immediately and TRUNCATED, without iterating.
 *     Returning an honest empty result instead would report a page that stopped
 *     early as a page that found nothing, which is the silent, plausible, wrong
 *     answer this tree is built to avoid.
 *
 * `perResourceSteps` defaults to the per-resource cap and exists as a parameter
 * for the same reason `expandOccurrences`'s own `maxSteps` does: the `min` above
 * is the load-bearing line in this function, and proving it takes a case on each
 * side of it. Reaching the real quarter-million from a test costs three quarters
 * of a second of genuine CPU per case, and a gate nobody can afford to assert is
 * a gate that stops being asserted. Production passes neither this nor `cap`.
 */
export function expandWithinBudget(
  resource: ParsedCalendarResource,
  rangeStartUtc: number,
  rangeEndUtc: number,
  budget: StepBudget,
  cap: number = MAX_EXPANDED_OCCURRENCES,
  perResourceSteps: number = MAX_ITERATOR_STEPS,
  keep: OccurrenceKeep = "starts",
): ExpansionResult {
  if (budget.remaining <= 0) {
    return {
      occurrences: [],
      truncated: true,
      steps: 0,
      preExpanded: resource.preExpanded,
    };
  }

  const result = expandOccurrences(
    resource,
    rangeStartUtc,
    rangeEndUtc,
    cap,
    Math.min(perResourceSteps, budget.remaining),
    keep,
  );

  // Clamped at zero rather than allowed to go negative. The step cap is checked
  // AFTER the increment inside the walk, so an expansion may overshoot its
  // allowance by exactly one step; a negative remaining would then read as an
  // allowance rather than as exhaustion at every `<= 0` test downstream.
  budget.remaining = Math.max(0, budget.remaining - result.steps);
  return result;
}

/**
 * One end of an event, read once and presented two ways.
 *
 * `local` is the wall clock a person would read off an invitation and `tzid` is
 * the zone it is expressed in; the two travel together because neither is
 * useful alone. `utc` is the instant, and its ABSENCE is meaningful rather than
 * incidental — see the field's own note.
 */
export interface EventTime {
  /** True when this is a date rather than an instant. */
  allDay: boolean;
  /** The wall clock: `YYYY-MM-DD` when `allDay`, otherwise `YYYY-MM-DDTHH:MM:SS`. */
  local: string;
  /**
   * The zone `local` is expressed in.
   *
   * The zone the RESOURCE ASKED FOR when it named one this server could not
   * resolve, so the request is reportable rather than lost. Otherwise the zone
   * actually resolved, which may be `UTC` or the library's floating sentinel
   * for a time that was anchored to nothing in the first place.
   */
  tzid: string;
  /**
   * Seconds since the epoch — **absent, not zero, when there is no instant.**
   *
   * Two shapes have no instant and both are omitted rather than guessed. An
   * all-day event is a date; midnight in some zone is a different claim from
   * the one the resource made. And a time whose zone could not be resolved is
   * a wall clock with nothing to anchor it: the seconds-since-epoch accessor
   * would read it as UTC and the host-runtime date accessor would read it in
   * the host machine's zone, which differ by the whole offset — so publishing
   * either as "the instant" publishes a number nobody computed, and the user
   * acts on it without ever being told there was a question.
   */
  utc?: number;
  /**
   * True when the resource named a zone it never defined.
   *
   * A statement about what this server did, not an error and not a fifth error
   * category — the same footing `unsupportedCharset` sits on in the mail search
   * result. There is nothing the caller can do differently, and the flag
   * already says what happened.
   */
  timezoneUnresolved: boolean;
}

/** A named party on an event: the organiser, or one attendee. */
export interface EventParticipant {
  /** The `CN` parameter, verbatim and untrusted. Null when absent. */
  name: string | null;
  /** The address, when the value is a `mailto:` URI. Null otherwise. */
  email: string | null;
  /**
   * The `PARTSTAT` parameter — whether they accepted. Verbatim and untrusted.
   *
   * **Reported verbatim rather than narrowed to a known set.** RFC 5545 lets a
   * client send an `X-`-prefixed value and lets a server define its own, so a
   * narrowing pass would turn an unrecognised-but-legitimate answer into
   * `null` — which reads as "they have not replied" when the truth is "this
   * server did not recognise the reply". Null means the property carried no
   * such parameter at all.
   */
  partstat: string | null;
  /**
   * The `ROLE` parameter — required, optional, or a chair. Verbatim, untrusted.
   *
   * Absent means absent. RFC 5545 defines a default of `REQ-PARTICIPANT` for a
   * missing `ROLE`, and substituting it here would publish a claim the
   * invitation never made as though the organiser had made it.
   */
  role: string | null;
  /**
   * The `SCHEDULE-STATUS` parameter — what the SERVER says it did about
   * telling this person. Verbatim and untrusted. Null when absent.
   *
   * **The server writes it, not the organiser, and it is fenced anyway.** RFC
   * 6638 §3.2.9 gives it a numeric form, which makes it look more like a
   * protocol constant than `PARTSTAT` does — and 03-10's audit found the
   * protocol-guaranteed category EMPTY on this surface, because every candidate
   * that looked fixed admitted free text on inspection. This one admits a
   * status DESCRIPTION after the code and a comma-separated list of them, so it
   * is a string somebody else chose. The test is "did a stranger choose it",
   * never "does it look like a protocol value".
   *
   * A trusted-block answer is derived from it by MATCHING against a fixed
   * table and publishing the table's own constant — see `deliveryReportOf` in
   * `./calendar.ts`. The raw value never leaves the fence.
   */
  scheduleStatus: string | null;
}

/** One occurrence of one event, after expansion. */
export interface Occurrence {
  /** The resource's UID. Shared by a master and every override on it. */
  uid: string | null;
  /**
   * The MASTER SERIES' key for this occurrence, in iCalendar form.
   *
   * Stable across an edit — an occurrence someone moved keeps the id of the
   * slot it was moved OUT of — which is exactly what makes it the right
   * discriminator for an occurrence identifier. Null for a non-recurring event,
   * which has one occurrence and needs no discriminator.
   */
  recurrenceId: string | null;
  /** True when the event carries a recurrence rule, or arrived expanded. */
  isRecurring: boolean;
  /** True when a human edited THIS occurrence away from the series. */
  isOverride: boolean;
  start: EventTime;
  end: EventTime;
  /** Untrusted. Verbatim. Null when the property is absent. */
  summary: string | null;
  /** Untrusted. Verbatim. Null when the property is absent. */
  location: string | null;
  /** Untrusted. Verbatim. Null when the property is absent. */
  description: string | null;
  /** Untrusted. Verbatim. Null when the property is absent. */
  organizer: EventParticipant | null;
  /** Untrusted. Verbatim. Empty when the event names nobody. */
  attendees: EventParticipant[];
}

/** One calendar resource, parsed and ready to expand. */
export interface ParsedCalendarResource {
  /**
   * The `VCALENDAR` the components were read out of, kept whole.
   *
   * **Kept because a PATCH must preserve what it did not touch, and the parse
   * is the only place the untouched parts still exist.** `components` holds the
   * `VEVENT`s; everything else the resource carried — its own `PRODID`, its
   * `CALSCALE`, every `VTIMEZONE` definition, any `X-` property somebody's
   * client wrote — lives here and nowhere else. A writer that rebuilt the
   * wrapper from a template would drop all of it silently, which is exactly the
   * loss this project refused an update over until D-02 made every update a
   * patch; a writer that clones this has nothing to drop, so there is nothing
   * left to refuse.
   *
   * Never mutated by anything in this module. `serializeOccurrenceResource`
   * clones it before touching it, so a parsed resource can be serialised twice
   * and give the same answer both times.
   */
  vcalendar: IcalComponent;
  /** The UID every component of this resource shares. */
  uid: string | null;
  /**
   * True when the resource arrived ALREADY EXPANDED by the server.
   *
   * This project never asks for that — RFC 4791 §9.6.5 converts to UTC and
   * drops the `VTIMEZONE`, destroying exactly the information CAL-03 exists to
   * return. The flag is defensive: detecting the shape costs one predicate,
   * and the alternative is iterating a series that has no rule.
   */
  preExpanded: boolean;
  /** The component carrying the rule, or null when the resource has none. */
  master: IcalComponent | null;
  /** Every `VEVENT` in the resource, in document order. */
  components: IcalComponent[];
  /**
   * The zones this resource DEFINED inline, in the order it defined them.
   *
   * Every `VTIMEZONE` present in the body, whether or not this parse was the
   * one that put it in the process-global service — a definition the service
   * already held is still a definition this resource carried. That is the
   * count `isPreExpanded` needs, because the shape it detects is "the server
   * dropped the definitions", which is a fact about the BYTES and not about
   * registry state. Reading the owned list there instead would misread a
   * resource whose zone an earlier one happened to hold as server-expanded.
   */
  definedTzids: string[];
  /**
   * The subset of `definedTzids` this parse actually ADDED to the service.
   *
   * The removal list, and it is deliberately narrower than the one above:
   * withdrawing a zone this parse merely *encountered* would evict a
   * definition the enclosing resource legitimately owns and is still reading
   * times against. Only what was added here may be taken back — see
   * `withParsedResource`, which is what takes it back.
   */
  ownedTzids: string[];
}

/**
 * Which occurrences an expansion keeps (18-REVIEW CR-01).
 *
 * `starts`: an occurrence whose START is inside the range. A listing wants
 * this: two abutting pages then return every occurrence exactly once.
 *
 * `overlaps`: an occurrence any part of which is inside the range. A conflict
 * check wants this. An event that began before the range and is still running
 * — a three-day conference, a week out of office — overlaps the range, and the
 * server's time-range read returns it for that reason. Keeping only what starts
 * inside the range drops it, and the check then says nothing else is on the
 * calendar while it is.
 */
export type OccurrenceKeep = "starts" | "overlaps";

/** The result of expanding one resource over one range. */
export interface ExpansionResult {
  occurrences: Occurrence[];
  /**
   * True when a cap stopped the walk before the range was exhausted.
   *
   * Trusted: this server's own statement about what it did.
   */
  truncated: boolean;
  /**
   * Iterator steps this expansion actually spent.
   *
   * Reported so a listing can hold ONE allowance across every resource it walks
   * (WR-01) — see `MAX_LISTING_ITERATOR_STEPS`. It counts rule iteration and
   * nothing else, which is the axis that is unbounded: a masterless resource is
   * a finite component list already parsed and in memory, bounded by the bytes
   * the server sent rather than by anyone's recurrence frequency, so it spends
   * none of this budget and reports zero.
   */
  steps: number;
  /** Mirrors `ParsedCalendarResource.preExpanded`, so the caller need not re-read it. */
  preExpanded: boolean;
}

/**
 * Parse one calendar resource body.
 *
 * Three steps, and THE ORDER IS LOAD-BEARING:
 *
 *   1. Register every timezone the resource defines, before any time is read
 *      from it. `ICAL.TimezoneService` ships with ZERO zones, and an
 *      unresolvable identifier neither throws nor warns — the time silently
 *      becomes floating. iCloud does normally ship the definitions, so this
 *      step is what makes the ordinary case correct rather than accidentally
 *      correct.
 *   2. Detect the already-expanded shape, so it is never iterated as a series
 *      it does not have.
 *   3. Separate the master component from its overrides. One resource may hold
 *      a master plus N overrides sharing one UID.
 *
 * Throws `DavConnectError` on a body that is not a calendar resource. That is
 * the "came back unusable" branch of the class's own docstring, and it is
 * deliberately a REFUSAL rather than a partial object (T-03-16): a caller
 * cannot tell a half-built result from a real one. No fifth error category is
 * invented, and nothing is read off the caught value.
 *
 * **This function REGISTERS into process-global state, so it is half of a
 * pair.** Every caller that reads a time off the result owes a matching
 * release, and `withParsedResource` below is the form that cannot forget —
 * prefer it. Calling this directly is for a caller that reads only structural
 * fields (`uid`, `master`, `preExpanded`, the two tzid lists), which are plain
 * data and outlive the registration.
 */
export function parseCalendarResource(icsText: string): ParsedCalendarResource {
  let vcalendar: IcalComponent;
  try {
    vcalendar = new ICAL.Component(ICAL.parse(icsText));
  } catch {
    // Nothing is read from the caught value — not its message, not its stack.
    throw new DavConnectError();
  }
  if (vcalendar.name !== "vcalendar") throw new DavConnectError();

  const { definedTzids, ownedTzids } = registerInlineTimezones(vcalendar);
  const components = vcalendar.getAllSubcomponents("vevent");
  const master = components.find((c) => !c.hasProperty("recurrence-id")) ?? null;

  return {
    vcalendar,
    uid: textOf((master ?? components[0])?.getFirstPropertyValue("uid")),
    // The DEFINED count, never the owned one. See the field's own note.
    preExpanded: isPreExpanded(components, definedTzids.length),
    master,
    components,
    definedTzids,
    ownedTzids,
  };
}

/**
 * Split a subscription feed's flat dump of independent `VEVENT`s into one
 * self-contained synthetic resource per UID.
 *
 * **Why this exists at all, and why `parseCalendarResource` cannot be handed a
 * feed directly.** A `CS:source` feed is not one calendar object resource with
 * a master and its overrides — it is every event the publisher has ever
 * published, concatenated into one `VCALENDAR`, sharing no UID at all (the
 * debug session measured the real feed this project has seen: 34 `VEVENT`s,
 * 34 distinct UIDs, zero `RECURRENCE-ID`, zero `RRULE`). `parseCalendarResource`
 * picks its `master` as the FIRST component with no `recurrence-id` — correct
 * for a real DAV object, where that is always true of at most one series, and
 * silently wrong here, where it is true of every one of the 34 and only the
 * first survives. This function is what stands between the feed's shape and
 * that mis-selection: each returned entry holds exactly one UID's components,
 * so the existing master/override machinery downstream sees the shape it was
 * built for.
 *
 * **Not built on `withParsedResource`.** This does its own raw parse and its
 * own component walk, because the whole point is to see the feed's `VEVENT`s
 * BEFORE anything picks a master among them — the very step this function
 * exists to avoid running over the whole feed at once.
 *
 * A `VEVENT` naming no `UID` at all is skipped rather than grouped under a
 * synthetic key: a resource this module cannot address is a resource it must
 * not pretend to have, on `collectionsFrom`'s own precedent one protocol layer
 * over.
 *
 * Each synthetic resource carries: every `VTIMEZONE` the feed itself defined
 * that this UID's components actually reference (cloned, never the shared
 * original — see `cloneComponent`, since the same feed-level definition may be
 * referenced by several UID groups and must not be reparented out from under
 * an entry already built); every alias-derived `VTIMEZONE` this group needs
 * and the feed did not itself define (see `aliasedZoneDefinitionOf`); and
 * every `VEVENT` component in the group, cloned for the same reason. Silently
 * omitted when neither the feed nor the alias table can produce a definition
 * for an identifier a component names — `readEventTime`'s existing unresolved-
 * zone branch reports that honestly downstream, exactly as it already does for
 * any resource naming an undefined zone today. Never guess; absence over a
 * wrong number.
 *
 * Each entry's text is assembled by the same template
 * `serializeCalendarResource` already uses — one `VERSION`, this server's own
 * `PRODID`, the zone definitions, then the components, then the same trailing
 * `\r\n` — so the two writers cannot drift into two different ideas of what a
 * well-formed resource looks like.
 *
 * Throws `DavConnectError` on a body that is not a calendar resource at all,
 * on `parseCalendarResource`'s own precedent: a caller cannot tell a half-built
 * result from a real one, so a body this cannot parse is a refusal rather than
 * an empty list.
 */
export function splitSubscriptionFeed(
  icsText: string,
): { uid: string; icsText: string }[] {
  let vcalendar: IcalComponent;
  try {
    vcalendar = new ICAL.Component(ICAL.parse(icsText));
  } catch {
    // Nothing is read from the caught value.
    throw new DavConnectError();
  }
  if (vcalendar.name !== "vcalendar") throw new DavConnectError();

  const feedTimezones = vcalendar.getAllSubcomponents("vtimezone");
  const feedVevents = vcalendar.getAllSubcomponents("vevent");

  const groups = new Map<string, IcalComponent[]>();
  for (const vevent of feedVevents) {
    const uid = textOf(vevent.getFirstPropertyValue("uid"));
    if (uid === null) continue;
    const group = groups.get(uid);
    if (group === undefined) groups.set(uid, [vevent]);
    else group.push(vevent);
  }

  const entries: { uid: string; icsText: string }[] = [];

  for (const [uid, components] of groups) {
    const referencedTzids = new Set<string>();
    for (const component of components) {
      const startTzid = requestedTzidOf(component, "dtstart");
      if (startTzid !== null) referencedTzids.add(startTzid);
      const endTzid = endTzidOf(component);
      if (endTzid !== null) referencedTzids.add(endTzid);
    }

    const feedDefinitions = feedTimezones.filter((definition) => {
      const tzid = textOf(definition.getFirstPropertyValue("tzid"));
      return tzid !== null && referencedTzids.has(tzid);
    });
    const feedDefinedTzids = new Set(
      feedDefinitions
        .map((definition) => textOf(definition.getFirstPropertyValue("tzid")))
        .filter((tzid): tzid is string => tzid !== null),
    );

    const synthetic = new ICAL.Component("vcalendar");
    synthetic.addPropertyWithValue("version", "2.0");
    synthetic.addPropertyWithValue("prodid", PRODID);

    for (const definition of feedDefinitions) {
      synthetic.addSubcomponent(cloneComponent(definition));
    }
    for (const tzid of referencedTzids) {
      if (feedDefinedTzids.has(tzid)) continue;
      const definitionText = aliasedZoneDefinitionOf(tzid);
      if (definitionText === null) continue;
      synthetic.addSubcomponent(new ICAL.Component(ICAL.parse(definitionText)));
    }
    for (const component of components) {
      synthetic.addSubcomponent(cloneComponent(component));
    }

    entries.push({ uid, icsText: `${synthetic.toString()}\r\n` });
  }

  return entries;
}

/**
 * Parse a resource, use it, and take its timezones back out again (CR-03).
 *
 * **`ICAL.TimezoneService` is a process-global singleton whose lifetime is the
 * ISOLATE's, not the request's**, keyed by identifier, first-definition-wins,
 * with no notion of whether two definitions bearing one name agree. On Workers
 * that registry survives across requests. So a single invitation from a
 * stranger carrying a `VTIMEZONE` that claims `America/New_York` with
 * fabricated offsets silently re-anchors that name for every later resource in
 * the isolate — in later requests, on the user's own calendars. The instant
 * published is then wrong by the fabricated offset, and `timezoneUnresolved`
 * reads FALSE while it happens, because the zone did resolve. The one field
 * built to say "do not trust this instant" vouches for the wrong one.
 *
 * **Which resource that reaches is narrower than it sounds, and knowing the
 * boundary is what keeps this fix honest.** `ICAL.Time.fromDateTimeString`
 * resolves a `TZID` from the resource's OWN component tree first, via
 * `Component.getTimeZoneByID`, and consults the service only when the tree
 * holds no matching `VTIMEZONE`. A compliant self-defining resource is
 * therefore immune. The victim is a resource that NAMES a zone and does not
 * define it — the shape this module already reports as unresolved, which
 * without a registry boundary stops being reported and starts resolving
 * against a stranger's definition instead. Measured, not assumed: with the
 * release disabled, `test/dav-icalendar.test.ts` reads such a resource
 * fourteen hours out with the flag reading false.
 *
 * This bounds the registration to the parse that made it. Registry state
 * cannot cross a resource boundary, so an occurrence's instant is a function
 * of that resource's own bytes again — which is also the property
 * `sortInstantOf` and the keyset cursor rest on: page two must recompute the
 * identical key for the identical row, and it cannot if the key depends on
 * which resources a warm isolate happened to see first.
 *
 * **The release is HERE rather than at the end of `parseCalendarResource`,
 * and the reason is stated carefully because the measurement is narrower than
 * the intuition.** Zone resolution is lazy — the expansion reads `DTSTART` off
 * the component and looks the identifier up at that moment, after the parse
 * has returned — so releasing at the end of the parse LOOKS like it would
 * float the resource's own times. Against this library version it does not:
 * the component-tree lookup above serves the self-defining case, and moving
 * the release into the parse leaves the whole suite green. The scope form is
 * kept anyway, on two grounds that do not depend on that measurement holding.
 * It preserves this module's documented order — every zone registered before
 * any time is read from it — so the registration is a real fallback for any
 * path that builds a time without a property to walk up from, rather than
 * dead code that happens not to be exercised. And it is the form that stays
 * correct if the library's preference order ever changes, which a release
 * timed to the parse would not.
 *
 * Only `ownedTzids` is withdrawn — see that field. A nested parse that merely
 * encountered an outer resource's zone must not evict it.
 */
export function withParsedResource<T>(
  icsText: string,
  use: (resource: ParsedCalendarResource) => T,
): T {
  const resource = parseCalendarResource(icsText);
  try {
    return use(resource);
  } finally {
    // `finally`, so a throw out of the expansion cannot leak the registration
    // it would otherwise leave behind — the hostile shapes are exactly the
    // ones most likely to raise on the way past.
    releaseTimezones(resource.ownedTzids);
  }
}

/**
 * Expand one resource into the occurrences that fall inside a range.
 *
 * **The boundary rule is half-open and it is stated once here for both edges:
 * an occurrence starting exactly at `rangeStartUtc` is IN, and one starting
 * exactly at `rangeEndUtc` is OUT.** That is the whole answer to the adjacency
 * question — two abutting ranges return every occurrence exactly once between
 * them, with no gap and no duplicate.
 *
 * The range is given in seconds since the epoch rather than as a date, so this
 * function reads nothing from the host runtime and produces the same answer in
 * the vitest pool as it does in a production isolate.
 *
 * A NON-RECURRING event goes through the same path and yields exactly one
 * occurrence: the iterator works on an event with no rule, returning its start
 * once. There is no second code path to keep in step.
 *
 * One nuance worth knowing, because it is a real behaviour rather than an
 * accident: an occurrence is filtered on the MASTER SERIES' slot, not on the
 * time an override moved it to. A meeting moved from inside the range to
 * outside it still appears, at its moved time. That falls out of the iterator
 * walking recurrence ids, and it is the correct reading — the caller asked
 * which slots of this series fall in the range.
 *
 * `keep` widens the start edge only, and only when asked: under `overlaps` an
 * occurrence that started before the range but has not ended by its start is
 * kept too (see `OccurrenceKeep`). The end edge is the same in both modes.
 * Listings pass nothing and keep the half-open rule above.
 */
export function expandOccurrences(
  resource: ParsedCalendarResource,
  rangeStartUtc: number,
  rangeEndUtc: number,
  cap: number = MAX_EXPANDED_OCCURRENCES,
  maxSteps: number = MAX_ITERATOR_STEPS,
  keep: OccurrenceKeep = "starts",
): ExpansionResult {
  const rangeStart = utcTimeAt(rangeStartUtc);
  const rangeEnd = utcTimeAt(rangeEndUtc);

  // The path is chosen by the ABSENCE OF A MASTER rather than by the
  // `preExpanded` flag, and the difference matters. The flag is the strict
  // three-part shape a server-side expansion produces; a resource can lose its
  // master some other way — an override synchronised without its series, say —
  // and iterating a null master would return nothing at all while the
  // components sat right there. Structural check for the path, flag for the
  // report.
  return resource.master === null
    ? expandComponents(resource, rangeStart, rangeEnd, cap, keep)
    : expandSeries(resource, rangeStart, rangeEnd, cap, maxSteps, keep);
}

/**
 * Select ONE occurrence of a parsed resource by its recurrence id (CAL-03).
 *
 * **This exists because a detail fetch has no range, and every windowed
 * substitute for one has a rule frequency that breaks it.** `expandOccurrences`
 * is correct and is what a LISTING wants: it is given a range, and its two caps
 * bound the cost of reaching that range. A detail call arrives with an
 * occurrence identifier and nothing else — no range, and no honest way to
 * invent one. Guessing a wide window is not a smaller version of this function,
 * it is a different and wrong one: the occurrence cap counts results from the
 * SERIES START, so a sub-minute rule exhausts it inside a day and the requested
 * occurrence — which a listing returned moments earlier — comes back as
 * not-found. A detail fetch that refuses an event the listing just showed is
 * exactly the silent, plausible, wrong answer this tree is built to avoid.
 *
 * So the walk stops at the MATCH rather than at a horizon. It costs no more
 * than the same resource costs inside a listing, and it is bounded by the same
 * iterator-step cap — an unbounded rule whose target is never reached returns
 * `null`, which the caller reports as not-found rather than as a nearest
 * neighbour.
 *
 * `recurrenceId` is compared in WIRE form, which is what the opaque identifier
 * carries and what `occurrenceFrom` reports. `null` selects the single
 * occurrence of a non-recurring event, and it is a real comparison rather than
 * a special case: a non-recurring event's occurrence key IS null.
 *
 * Returns `null` when the resource no longer produces that occurrence — the
 * organiser deleted the date, or changed the rule. Never a neighbour.
 */
export function findOccurrence(
  resource: ParsedCalendarResource,
  recurrenceId: string | null,
  maxSteps: number = MAX_ITERATOR_STEPS,
): Occurrence | null {
  // A masterless resource — the server-expanded shape, or an override
  // synchronised without its series — has a FINITE component list already in
  // memory, so there is nothing to bound. The cap is the list's own length.
  if (resource.master === null) {
    const { occurrences } = expandComponents(
      resource,
      utcTimeAt(WIDEST_INSTANT_START),
      utcTimeAt(WIDEST_INSTANT_END),
      resource.components.length,
    );
    return occurrences.find((one) => one.recurrenceId === recurrenceId) ?? null;
  }

  const series = new ICAL.Event(resource.master);

  // **Relate every override BEFORE iterating**, exactly as the range expansion
  // does. Skipping it is Pitfall 6: the moved occurrence comes back at the
  // master's time under the master's summary, with no error anywhere — and on
  // a detail call that is the whole answer rather than one row of twelve.
  for (const component of resource.components) {
    const candidate = new ICAL.Event(component);
    if (candidate.isRecurrenceException()) series.relateException(candidate);
  }

  const isRecurring = series.isRecurring();

  // Every slot of a recurring series has an occurrence key, so a reference
  // carrying none names nothing in one. Refused here rather than by walking an
  // unbounded rule to the step cap to discover the same thing.
  if (isRecurring && recurrenceId === null) return null;

  const iterator = series.iterator();
  let steps = 0;

  let next: IcalTime | null | undefined = iterator.next();
  while (next) {
    steps += 1;
    if (steps > maxSteps) return null;

    // The iterator yields the MASTER SERIES' slot, which is exactly what the
    // occurrence key is — stable across an edit, so a moved occurrence is found
    // under the slot it was moved out of rather than under its new time.
    const key = isRecurring ? next.toICALString() : null;
    if (key === recurrenceId) {
      return occurrenceFrom(series.getOccurrenceDetails(next), isRecurring);
    }

    // **Stop once the walk has passed the slot asked for.** Without this an
    // occurrence the organiser deleted costs the FULL step cap — a quarter of a
    // million iterations to answer "no", on an unbounded weekly rule that a
    // real calendar is mostly made of. Measured, not theorised: it is what
    // turned two cases of this suite into five-second timeouts.
    //
    // Compared as WIRE STRINGS rather than as instants, and that is precision
    // rather than laziness. Every slot of one series renders in the same shape,
    // because they all descend from one `DTSTART` — same date-versus-date-time,
    // same zone, same length — so their lexicographic order IS their time
    // order. Parsing the reference back into a time instead would have to
    // decide what zone a bare wall clock is in, which is the floating-time
    // ambiguity this module exists to keep out of comparisons.
    //
    // A reference whose shape does not match the series at all terminates the
    // walk early and yields `null`, which is the right answer: nothing in this
    // series has that key.
    if (key !== null && recurrenceId !== null && key > recurrenceId) return null;

    next = iterator.next();
  }

  return null;
}

/** What one resource's `VTIMEZONE` set defined, split by who now owns it. */
interface InlineTimezones {
  /** Every identifier the resource defined, in document order. */
  definedTzids: string[];
  /** The ones this call added, and therefore the ones it may take back. */
  ownedTzids: string[];
}

/**
 * Register every `VTIMEZONE` the resource carries, and say which are ours.
 *
 * Guarded against re-registering an identifier already present, because the
 * service is process-global: the first definition of a given identifier in an
 * isolate wins for every later resource. Under `withParsedResource` that window
 * is now one resource wide rather than one isolate wide, which is what makes
 * the guard safe rather than merely conventional — but the guard still matters
 * INSIDE the window, where a nested parse must not displace the outer
 * resource's zone out from under the times it is still reading.
 *
 * **The two lists are not the same list and the difference is load-bearing.**
 * `definedTzids` answers "what did these bytes define", which is what
 * `isPreExpanded` asks. `ownedTzids` answers "what did this call put into
 * global state", which is what the release must withdraw. Conflating them
 * evicts a zone somebody else owns.
 *
 * A definition the library refuses — a `VTIMEZONE` with no `TZID` makes
 * `register` raise — takes the whole resource down as unusable, on the same
 * footing as a body that would not parse. Anything already added is withdrawn
 * FIRST, so a refusal cannot be the thing that leaks a registration.
 */
function registerInlineTimezones(vcalendar: IcalComponent): InlineTimezones {
  const definedTzids: string[] = [];
  const ownedTzids: string[] = [];
  try {
    for (const definition of vcalendar.getAllSubcomponents("vtimezone")) {
      const zone = new ICAL.Timezone(definition);
      definedTzids.push(zone.tzid);
      if (ICAL.TimezoneService.has(zone.tzid)) continue;
      ICAL.TimezoneService.register(zone);
      ownedTzids.push(zone.tzid);
    }
  } catch {
    // Nothing is read from the caught value — not its message, not its stack.
    releaseTimezones(ownedTzids);
    throw new DavConnectError();
  }
  return { definedTzids, ownedTzids };
}

/**
 * Withdraw a set of identifiers from the process-global service.
 *
 * Takes the OWNED list and nothing else. There is deliberately no "clear
 * everything" form here: the service's own reset would take out zones a
 * resource further up the stack is still resolving against, and a fix that
 * unregisters somebody else's zone is the same class of silent wrongness as
 * the poisoning it was written to stop.
 */
function releaseTimezones(tzids: string[]): void {
  for (const tzid of tzids) ICAL.TimezoneService.remove(tzid);
}

/**
 * The shape a server-side `<C:expand>` leaves behind.
 *
 * Every component carries a recurrence id, none carries a rule, and no zone is
 * defined — because the expansion converted everything to UTC and dropped the
 * definitions. All three clauses together, because each alone describes
 * something else: a resource of pure overrides still has zones, and a resource
 * with no rule may simply be a single event.
 */
function isPreExpanded(components: IcalComponent[], definedZones: number): boolean {
  return (
    components.length > 0 &&
    definedZones === 0 &&
    components.every((c) => c.hasProperty("recurrence-id")) &&
    components.every((c) => !c.hasProperty("rrule"))
  );
}

/** Expand a resource that has a master component, by iterating its rule. */
function expandSeries(
  resource: ParsedCalendarResource,
  rangeStart: IcalTime,
  rangeEnd: IcalTime,
  cap: number,
  maxSteps: number,
  keep: OccurrenceKeep = "starts",
): ExpansionResult {
  const series = new ICAL.Event(resource.master ?? undefined);

  // **Relate every override BEFORE any iteration.** Skipping this is the silent
  // failure Pitfall 6 names: an occurrence someone moved comes back with the
  // master's time and the master's summary, with no error anywhere.
  for (const component of resource.components) {
    const candidate = new ICAL.Event(component);
    if (candidate.isRecurrenceException()) series.relateException(candidate);
  }

  const isRecurring = series.isRecurring();
  const iterator = series.iterator();
  const occurrences: Occurrence[] = [];
  let truncated = false;
  let steps = 0;

  // Under `overlaps`, a slot before the range needs its details only if it
  // could still be running. With no edited dates, every slot lasts exactly the
  // series' own duration, so its end is known without reading its details —
  // and the details read doubles the cost of a walk from a series start years
  // back. With edited dates, any slot may have been moved or lengthened, so
  // every early slot is read.
  const plainSlots = keep === "overlaps" && Object.keys(series.exceptions).length === 0;
  const slotSeconds = plainSlots ? series.duration.toSeconds() : 0;
  const rangeStartSeconds = rangeStart.toUnixTime();

  // The iterator starts at the series' own start, NOT at the range start, so
  // the caller skips forward and breaks at the end. **That break is what
  // terminates an unbounded rule** — there is nothing else that would.
  let next: IcalTime | null | undefined = iterator.next();
  while (next) {
    steps += 1;
    if (steps > maxSteps) {
      truncated = true;
      break;
    }
    if (next.compare(rangeEnd) >= 0) break;
    // A slot before the range is still kept under `overlaps` when the date it
    // produces has not ended by the range's start. Its details are read only
    // then, so a listing pays nothing for the mode it does not use.
    const details =
      next.compare(rangeStart) >= 0
        ? series.getOccurrenceDetails(next)
        : keep === "overlaps" &&
            (!plainSlots || next.toUnixTime() + slotSeconds > rangeStartSeconds)
          ? runningAt(series.getOccurrenceDetails(next), rangeStart, rangeEnd)
          : null;
    if (details !== null) {
      if (occurrences.length >= cap) {
        truncated = true;
        break;
      }
      occurrences.push(occurrenceFrom(details, isRecurring));
    }
    next = iterator.next();
  }

  return { occurrences, truncated, steps, preExpanded: resource.preExpanded };
}

/**
 * The details of a date that began before the range, when it is still running
 * inside it, else null.
 *
 * Compared as the occurrence actually stands, so a date someone moved is judged
 * at its moved time. An end exactly at the range's start is out: the date ended
 * as the range began, which is touching and not overlapping.
 */
function runningAt(
  details: OccurrenceDetails,
  rangeStart: IcalTime,
  rangeEnd: IcalTime,
): OccurrenceDetails | null {
  if (details.endDate.compare(rangeStart) <= 0) return null;
  if (details.startDate.compare(rangeEnd) >= 0) return null;
  return details;
}

/**
 * Return a masterless resource as its own components.
 *
 * Document order is preserved rather than imposed. Ordering across resources is
 * the service layer's job (it owns the total order the cursor rides), and a
 * sort here would be a second, weaker one.
 */
function expandComponents(
  resource: ParsedCalendarResource,
  rangeStart: IcalTime,
  rangeEnd: IcalTime,
  cap: number,
  keep: OccurrenceKeep = "starts",
): ExpansionResult {
  const occurrences: Occurrence[] = [];
  let truncated = false;

  for (const component of resource.components) {
    const event = new ICAL.Event(component);
    const start = event.startDate;
    if (start.compare(rangeEnd) >= 0) continue;
    // Under `overlaps`, a component that began before the range is kept while
    // it is still running at the range's start (see `OccurrenceKeep`).
    if (start.compare(rangeStart) < 0) {
      if (keep !== "overlaps") continue;
      if (event.endDate.compare(rangeStart) <= 0) continue;
    }
    if (occurrences.length >= cap) {
      truncated = true;
      break;
    }

    const recurrenceId = component.getFirstPropertyValue("recurrence-id");
    occurrences.push({
      uid: textOf(component.getFirstPropertyValue("uid")),
      recurrenceId: recurrenceId instanceof ICAL.Time ? recurrenceId.toICALString() : null,
      isRecurring: true,
      // **In a server-expanded resource the recurrence id is the server's own
      // bookkeeping, not a record of anyone's edit** — every component carries
      // one — so reporting them all as overrides would invent an edit that
      // never happened. A masterless resource that is NOT the expanded shape is
      // the other case: those components really are exceptions, orphaned.
      isOverride: !resource.preExpanded,
      start: readEventTime(start, requestedTzidOf(component, "dtstart")),
      end: readEventTime(event.endDate, endTzidOf(component)),
      summary: textOf(event.summary),
      location: textOf(event.location),
      description: textOf(event.description),
      organizer: participantFrom(component.getFirstProperty("organizer")),
      attendees: participantsFrom(component.getAllProperties("attendee")),
    });
  }

  // ZERO steps, and that is a claim rather than an omission: this walk iterates
  // no recurrence rule. Its length is `resource.components.length`, already
  // parsed and already in memory, so it is bounded by the response the server
  // sent rather than by a frequency a stranger chose — which is precisely the
  // axis the listing budget exists to bound. See `ExpansionResult.steps`.
  return { occurrences, truncated, steps: 0, preExpanded: resource.preExpanded };
}

/**
 * Build one occurrence from the library's details object.
 *
 * `recurrenceId` is the MASTER-series key and is stable across an override;
 * `startDate`, `endDate` and `item` carry the OVERRIDE's values when one
 * applies. Reading the master's component here instead of `item`'s is the
 * half-applied-override bug in its other form.
 */
function occurrenceFrom(details: OccurrenceDetails, isRecurring: boolean): Occurrence {
  const item = details.item;
  const component = item.component;
  return {
    uid: textOf(component.getFirstPropertyValue("uid")),
    recurrenceId: isRecurring ? details.recurrenceId.toICALString() : null,
    isRecurring,
    isOverride: item.isRecurrenceException(),
    start: readEventTime(details.startDate, requestedTzidOf(component, "dtstart")),
    end: readEventTime(details.endDate, endTzidOf(component)),
    summary: textOf(item.summary),
    location: textOf(item.location),
    description: textOf(item.description),
    organizer: participantFrom(component.getFirstProperty("organizer")),
    attendees: participantsFrom(component.getAllProperties("attendee")),
  };
}

/**
 * Read one end of an event, and say plainly what could not be established.
 *
 * **The host-runtime date accessor is never used anywhere in this tree**, and
 * the reason is measured rather than stylistic: it reads a floating time in the
 * HOST MACHINE's zone while the seconds-since-epoch accessor reads the same
 * value as UTC, and the vitest pool inherits the host's zone while production
 * Workers run UTC. A conversion through it is green in the suite and wrong in
 * production. The wall clock below is assembled from the time's own calendar
 * fields for the same reason — it cannot acquire a host dependency later.
 *
 * `requestedTzid` is the identifier the RESOURCE named on the property, which
 * the caller reads off the component. It is the only evidence available when
 * the zone did not resolve, so it is what gets reported.
 */
function readEventTime(value: IcalTime, requestedTzid: string | null): EventTime {
  const allDay = value.isDate;
  const resolved = value.zone.tzid;
  const floating = resolved === FLOATING_TZID;

  // An all-day date is anchored to nothing BY DEFINITION, so it is not an
  // unresolved zone — nothing was asked for and nothing failed. A date-time
  // with no zone parameter is floating by the author's choice, which is also
  // not a failure. Only a named-but-undefined zone is.
  const unresolvedTzid = !allDay && floating ? requestedTzid : null;

  const time: EventTime = {
    allDay,
    local: wallClock(value),
    tzid: unresolvedTzid ?? resolved,
    timezoneUnresolved: unresolvedTzid !== null,
  };
  // Assigned rather than spread, so the key is genuinely ABSENT when there is
  // no instant. `utc: undefined` would serialise away but still answer `true`
  // to an `in` check, and "the field is missing" is the claim being made.
  if (!allDay && !floating) time.utc = value.toUnixTime();
  return time;
}

/**
 * The wall clock, assembled from the time's own fields.
 *
 * Not the library's own string form, which appends a `Z` for a UTC time and
 * would make `local` mean two different things depending on the zone. This is
 * one shape: a date when the value is a date, a date-time otherwise, never an
 * offset and never a suffix.
 */
function wallClock(value: IcalTime): string {
  const pad = (n: number, width = 2): string => String(n).padStart(width, "0");
  const date = `${pad(value.year, 4)}-${pad(value.month)}-${pad(value.day)}`;
  if (value.isDate) return date;
  return `${date}T${pad(value.hour)}:${pad(value.minute)}:${pad(value.second)}`;
}

/**
 * The widest instants this module will construct, in seconds since the epoch.
 *
 * Year one and year 9999 — the bounds `ICAL.Time` itself is written against.
 * They exist for ONE caller, `findOccurrence`'s masterless branch, where the
 * component list is finite and already in memory so a range is pure ceremony.
 * They are deliberately not reachable from any path that iterates a rule: an
 * unbounded rule walked to year 9999 is the cost failure the two caps exist to
 * prevent.
 */
const WIDEST_INSTANT_START = -62135596800;
const WIDEST_INSTANT_END = 253402300799;

/** A UTC `ICAL.Time` at an instant, built without touching the host runtime. */
function utcTimeAt(seconds: number): IcalTime {
  const value = ICAL.Time.epochTime.clone();
  value.addDuration(ICAL.Duration.fromSeconds(seconds));
  return value;
}

/** The `TZID` parameter a component's property names, if it names one. */
function requestedTzidOf(component: IcalComponent, propertyName: string): string | null {
  const property = component.getFirstProperty(propertyName);
  if (property === null) return null;
  return firstParameter(property, "tzid");
}

/**
 * The zone for an event's end.
 *
 * Falls back to the start's zone, which is not a guess: when `DTEND` is absent
 * the library reports an end EQUAL to the start, so the start's zone is the
 * zone that value is actually expressed in.
 */
function endTzidOf(component: IcalComponent): string | null {
  return requestedTzidOf(component, "dtend") ?? requestedTzidOf(component, "dtstart");
}

/**
 * One parameter value, however many the property carries.
 *
 * The accessor hands back an ARRAY when a property has several of a parameter
 * and a BARE STRING when it has one. Indexing the string would yield a
 * character, which is silently wrong rather than an error.
 */
function firstParameter(property: IcalProperty, name: string): string | null {
  const value = property.getParameter(name);
  if (Array.isArray(value)) return typeof value[0] === "string" ? value[0] : null;
  return typeof value === "string" ? value : null;
}

/** A participant from an `ORGANIZER` or `ATTENDEE` property. Untrusted, verbatim. */
function participantFrom(property: IcalProperty | null): EventParticipant | null {
  if (property === null) return null;
  const value = property.getFirstValue();
  const uri = typeof value === "string" ? value : null;
  const email =
    uri !== null && uri.toLowerCase().startsWith("mailto:") ? uri.slice(7) : null;
  return {
    name: firstParameter(property, "cn"),
    email,
    partstat: firstParameter(property, "partstat"),
    role: firstParameter(property, "role"),
    scheduleStatus: firstParameter(property, "schedule-status"),
  };
}

/** Every attendee on a component, in document order. */
function participantsFrom(properties: IcalProperty[]): EventParticipant[] {
  const participants: EventParticipant[] = [];
  for (const property of properties) {
    const participant = participantFrom(property);
    if (participant !== null) participants.push(participant);
  }
  return participants;
}

/**
 * Narrow a property value to a string, or to absence.
 *
 * The library's value accessors return a union covering every value type the
 * design set knows. Anything that is not a string is not text, and this module
 * reports absence rather than coercing — a coerced value is a value nobody
 * wrote.
 */
function textOf(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

// ---------------------------------------------------------------------------
// The BUILD side (CALW-01)
//
// Everything above reads a resource somebody else wrote. Everything below
// writes one, and it is in the same module for the reason the two halves of
// `src/mail/mime.ts` are: the format is one format, and a writer that lived
// somewhere else would grow its own idea of what a `VEVENT` is.
//
// Two properties hold this half together, and both are stated once here rather
// than repeated at each call site.
//
// **The library serialises; this file does not.** Folding at 75 OCTETS, TEXT
// escaping of `,` `;` `\` and newlines, and CRLF framing are all
// `Component#toString()`'s job. A hand-rolled writer works on the developer's
// test event and corrupts the first real one carrying a comma, and the octet
// half of the fold is the part a character-counting writer gets wrong on the
// first non-ASCII title — a lesson this project has now learned twice on the
// read side.
//
// **Nothing here touches `ICAL.TimezoneService`.** The zone rides on the
// property as a `TZID` PARAMETER and the definition rides in the resource as a
// `VTIMEZONE` SUBCOMPONENT, so there is nothing to resolve and therefore
// nothing to register. That matters because the service is a process-global
// singleton whose lifetime is the isolate's: a registration left behind by the
// build path would re-anchor that identifier for every later request in the
// same isolate, which is 03-REVIEW.md CR-03 arriving through a new door. The
// read side pays for the same property with `withParsedResource`'s
// register-and-withdraw scope; this side pays nothing, because it never asks.
// ---------------------------------------------------------------------------

/** Join `VTIMEZONE` content lines the way both this format and RFC 5545 do. */
function zoneBlock(...lines: string[]): string {
  return `${lines.join("\r\n")}\r\n`;
}

/**
 * One `VTIMEZONE` in the standard United States shape, post-2007 rules.
 *
 * DST begins on the second Sunday in March and ends on the first Sunday in
 * November, at 02:00 local, which is what the Energy Policy Act of 2005 has
 * meant for every year since 2007. The `DTSTART` in 1970 is the conventional
 * anchor the format uses and is the same one the read-side fixture carries; a
 * time before 2007 read against this definition would use today's rule, which
 * is a limitation of a two-rule table rather than a defect in this one, and it
 * is not reachable from a tool that creates an event.
 */
function usZone(
  tzid: string,
  standardName: string,
  standardOffset: string,
  daylightName: string,
  daylightOffset: string,
): string {
  return zoneBlock(
    "BEGIN:VTIMEZONE",
    `TZID:${tzid}`,
    "BEGIN:DAYLIGHT",
    `TZOFFSETFROM:${standardOffset}`,
    `TZOFFSETTO:${daylightOffset}`,
    `TZNAME:${daylightName}`,
    "DTSTART:19700308T020000",
    "RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU",
    "END:DAYLIGHT",
    "BEGIN:STANDARD",
    `TZOFFSETFROM:${daylightOffset}`,
    `TZOFFSETTO:${standardOffset}`,
    `TZNAME:${standardName}`,
    "DTSTART:19701101T020000",
    "RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU",
    "END:STANDARD",
    "END:VTIMEZONE",
  );
}

/**
 * The zones this server can anchor a created event to, and their definitions.
 *
 * **A BOUNDED TABLE, and the bound is the design rather than a shortcut.**
 * `ical.js` ships no timezone database — its `TimezoneService` is a registry
 * somebody populates, not a source of zone data — so a `TZID` this server holds
 * no definition for has exactly three outs, and two of them are wrong:
 *
 *   - Write the time in UTC. The event renders at the right instant today and
 *     at the wrong wall clock after the next transition, which is precisely the
 *     information loss the read side refuses when it declines server-side
 *     expansion.
 *   - Write `DTSTART;TZID=<zone>` with no definition beside it. That is the
 *     exact shape this server's OWN reader reports as `timezoneUnresolved`, so
 *     the round trip through `calendar_get_event` degrades on an event this
 *     server itself created. Writing resources one would flag as broken is a
 *     self-inflicted defect.
 *   - Derive the offsets from the host runtime. Host-zone dependent, green in
 *     the vitest pool and wrong in production — the `ical-jsdate` scan rule
 *     exists over exactly this failure shape.
 *
 * So the third out is to refuse, and to refuse WELL: a zone outside this table
 * comes back as a field on a SUCCESSFUL result rather than as a fifth error
 * category, on the footing `unsupportedCharset` already sits on. There is
 * nothing the caller can do differently, and the field already says what
 * happened.
 *
 * Adding a zone is adding an entry here. It is deliberately not a code change
 * anywhere else.
 */
export const VTIMEZONE_ALLOWLIST: Readonly<Record<string, string>> =
  Object.freeze({
    "America/New_York": usZone(
      "America/New_York",
      "EST",
      "-0500",
      "EDT",
      "-0400",
    ),
    "America/Chicago": usZone("America/Chicago", "CST", "-0600", "CDT", "-0500"),
    "America/Denver": usZone("America/Denver", "MST", "-0700", "MDT", "-0600"),
    "America/Los_Angeles": usZone(
      "America/Los_Angeles",
      "PST",
      "-0800",
      "PDT",
      "-0700",
    ),
    // One rule and no transitions. Present because "put it at 14:00 UTC" is a
    // real request and the alternative is refusing the one zone that needs no
    // table at all.
    UTC: zoneBlock(
      "BEGIN:VTIMEZONE",
      "TZID:UTC",
      "BEGIN:STANDARD",
      "TZOFFSETFROM:+0000",
      "TZOFFSETTO:+0000",
      "TZNAME:UTC",
      "DTSTART:19700101T000000",
      "END:STANDARD",
      "END:VTIMEZONE",
    ),
  });

/** Whether this server holds a definition for a zone, and can therefore anchor to it. */
export function isSupportedTimezone(tzid: string): boolean {
  return Object.prototype.hasOwnProperty.call(VTIMEZONE_ALLOWLIST, tzid);
}

/**
 * The definition for one zone, or null when this server holds none.
 *
 * **The guard above, applied at the two places that actually READ the table
 * (05-REVIEW.md WR-02).** Both of them indexed it directly and checked the
 * result against `undefined`, which is correct for a zone nobody defined and
 * wrong for one naming an inherited member of the object prototype: the table is
 * an object literal, so `VTIMEZONE_ALLOWLIST["constructor"]` hands back a
 * FUNCTION rather than `undefined`, sails past that check, and reaches the
 * parser as a zone definition. Both sites were safe only because every path to
 * them happens to run `isSupportedTimezone` first — safe by call ordering is a
 * property a refactor removes silently, and the correct form was already written
 * one function up.
 *
 * A `TZID` is read verbatim off a resource a stranger may have authored, which
 * is what makes this worth closing rather than noting.
 */
function zoneDefinitionOf(tzid: string): string | null {
  return isSupportedTimezone(tzid) ? VTIMEZONE_ALLOWLIST[tzid]! : null;
}

/**
 * Run a function against one of this server's five canonical zones, registered
 * for the duration of the call and withdrawn after it (SCHED-01).
 *
 * **The same scoped register-use-release discipline `withParsedResource`
 * applies to a stranger's inline `VTIMEZONE` (CR-03), applied here to one of
 * this server's OWN zones.** `ICAL.TimezoneService` is a process-global
 * singleton whose lifetime is the isolate's, so a registration left behind
 * would re-anchor that identifier for every later request in the same isolate.
 * The guard against re-registering an id already present is what keeps this
 * safe when a resource's own `VTIMEZONE` is already registered under the same
 * name — the outer registration is left alone and only what this call added is
 * withdrawn.
 *
 * Returns `null` — WITHOUT registering anything — for a zone outside the
 * allowlist, so the two exported converters below can report an unsupported
 * zone rather than throw, mirroring `createEvent`'s own early return.
 */
function withZone<T>(tzid: string, fn: (zone: IcalTimezone) => T): T | null {
  const definition = zoneDefinitionOf(tzid);
  if (definition === null) return null;

  const zone = new ICAL.Timezone({ component: definition, tzid });
  const owned = !ICAL.TimezoneService.has(tzid);
  if (owned) ICAL.TimezoneService.register(zone);
  try {
    return fn(zone);
  } finally {
    // `finally`, so a throw out of `fn` cannot leak the registration. Only what
    // this call added is withdrawn — an id an enclosing resource already owns
    // stays registered for the times it is still reading.
    if (owned) releaseTimezones([tzid]);
  }
}

/**
 * Convert a caller-supplied local wall clock and zone into a real UTC instant,
 * or `null` when the zone is outside this server's allowlist (SCHED-01).
 *
 * **Nothing in this codebase has previously needed this direction.** The write
 * path serialises wall-clock text and lets iCloud resolve it; the read path only
 * ever converts bytes iCloud already zone-resolved. Find-slots is the first
 * caller that holds a wall clock and a zone and must produce the instant itself,
 * client-side, to compute working-hours windows and day boundaries.
 *
 * A wall clock `ICAL.Time.fromDateTimeString` cannot parse throws
 * `DavConnectError`, mirroring `sortInstantOf`'s parser-failure convention — a
 * value that reached here unparseable is a value something upstream constructed
 * wrongly, not a caller error to answer plausibly.
 */
export function localTimeToUtc(wallClock: string, tzid: string): number | null {
  return withZone(tzid, (zone) => {
    let time: IcalTime;
    try {
      time = ICAL.Time.fromDateTimeString(wallClock);
    } catch {
      // Nothing is read from the caught value — not its message, not its stack.
      throw new DavConnectError();
    }
    // A wall clock parsed without a `Z` and without a property is floating; the
    // instant is fixed only once the zone is assigned. The cache the accessor
    // keeps is empty until the first read, so assigning the zone before the
    // read is what makes `toUnixTime` compute against it.
    time.zone = zone;
    return time.toUnixTime();
  });
}

/**
 * Convert a UTC instant into the local wall clock of one of this server's five
 * zones, or `null` when the zone is outside the allowlist (SCHED-01).
 *
 * The reverse of `localTimeToUtc`, and it reuses the same two building blocks
 * the read side already trusts: `utcTimeAt` builds a UTC `ICAL.Time` without
 * touching the host runtime, and `wallClock` renders a time from its own
 * calendar fields — never the library's string form, which would append a `Z`,
 * and never the host-runtime date accessor the `ical-jsdate` rule bans.
 */
export function utcToLocalTime(utcSeconds: number, tzid: string): string | null {
  return withZone(tzid, (zone) => wallClock(utcTimeAt(utcSeconds).convertToZone(zone)));
}

/**
 * Pre-IANA POSIX zone names, mapped to the modern identifier this server
 * already holds a definition for.
 *
 * **A subscription feed is read-side-only evidence that this alias table needs
 * to exist at all.** The debug session that led to this measured iCloud's own
 * older publishing path emitting `TZID=US/Pacific` with no inline `VTIMEZONE`
 * at all — a real subscription feed, not a hypothetical one. `readEventTime`
 * already reports an unresolvable name honestly rather than guessing, so
 * without this table every occurrence in that feed would carry
 * `timezoneUnresolved: true` and no instant, which is a correct-but-useless
 * answer for a zone this server could resolve if it only recognised the name.
 *
 * **Only aliased to a canonical name `VTIMEZONE_ALLOWLIST` already defines.**
 * Adding a fifth zone to that table is a decision made there, not smuggled in
 * here by widening the alias map past what the canonical table covers.
 */
const LEGACY_TZID_ALIASES: Readonly<Record<string, string>> = Object.freeze({
  "US/Pacific": "America/Los_Angeles",
  "US/Eastern": "America/New_York",
  "US/Central": "America/Chicago",
  "US/Mountain": "America/Denver",
});

/**
 * The `VTIMEZONE` definition for a legacy alias, registered under the
 * REQUESTED name rather than the canonical one.
 *
 * **The rewrite is load-bearing, not cosmetic.** `Component.getTimeZoneByID`
 * — which `ICAL.Time.fromDateTimeString` consults first, per
 * `withParsedResource`'s own docstring — looks a component tree up BY THE
 * EXACT IDENTIFIER a property named. An event whose `DTSTART` carries
 * `TZID=US/Pacific` needs a `VTIMEZONE` whose own `TZID:` line reads
 * `US/Pacific`; injecting `America/Los_Angeles`'s definition unchanged would
 * define a zone nothing on the resource asked for, and the lookup would miss
 * exactly as it did before this table existed.
 *
 * Returns `null` when the identifier has no alias, or when the alias names a
 * canonical zone this server holds no definition for (unreachable today, since
 * every value in the table above is a `VTIMEZONE_ALLOWLIST` key, but the
 * function does not assume that stays true forever).
 */
function aliasedZoneDefinitionOf(tzid: string): string | null {
  const canonical = LEGACY_TZID_ALIASES[tzid];
  if (canonical === undefined) return null;
  const definition = zoneDefinitionOf(canonical);
  if (definition === null) return null;
  return definition.replace(/^TZID:.*$/m, `TZID:${tzid}`);
}

/** The product identifier every resource this server writes carries. */
const PRODID = "-//icloud-mcp//EN";

/**
 * One reminder, in the only shape this server writes or reads back (D-01).
 *
 * **The narrowness is a decision, not a limitation, and the reason is
 * fidelity.** An alarm list is replaced as a WHOLE LIST — there is no way to
 * edit one entry by index and no way to edit one by value — which is the same
 * rule Phase 16 settled for a contact's emails and phones. Per-entry editing
 * needs a stable identity for each entry, and an alarm has none this server can
 * trust: a `VALARM` another client wrote may carry no `UID`, two alarms may be
 * byte-identical, and an index is a position in bytes somebody else is free to
 * reorder. Editing by index against bytes that moved edits the wrong alarm; that
 * is where fidelity gets lost, and it is lost silently.
 *
 * So the vocabulary is the smallest one that is honest about what it can
 * reproduce exactly:
 *
 * - **`minutesBefore`** — whole minutes before the event STARTS. An alarm
 *   expressed any other way (an absolute datetime, a reach from the END, a
 *   moment AFTER the start, a duration with a seconds remainder) is REPORTED as
 *   unmodelled by `alarmsOf` and never coerced into this field. See its
 *   docstring, which owns that argument.
 * - **`action`** — one literal value this phase, so a second one is a type
 *   change somebody decides rather than a string that happens to compile. An
 *   `AUDIO` or `EMAIL` alarm is a real alarm this server cannot express, which
 *   is exactly what the unmodelled count is for.
 *
 * Two shapes are DEFERRED by decision and recorded as such in
 * `17-CONTEXT.md`, so a later session reads a choice rather than an oversight: a
 * `VALARM` passed through verbatim, and an absolute `TRIGGER` datetime. Neither
 * is to be smuggled in as a widening of this type.
 */
export interface AlarmSpec {
  /** Whole minutes before the start. Zero means at the start. */
  minutesBefore: number;
  /** The one action this phase writes. */
  action: "display";
}

/**
 * What a component's alarms look like to a server that models only one shape.
 *
 * Two numbers rather than one list, because "this server found no reminder" and
 * "this server found a reminder it cannot express" are different facts and the
 * user is entitled to the second one. A whole-list replacement removes an
 * unmodelled alarm along with the rest, so the confirmation line names the count
 * before the user agrees — see `composeConfirmationLine`'s alarm clause.
 */
export interface AlarmReading {
  /** Every alarm this server could express, in document order. */
  modelled: AlarmSpec[];
  /** How many alarms it could not. Their values are deliberately not reported. */
  unmodelled: number;
}

/** The wire spelling of the one action `AlarmSpec` admits. */
const ALARM_ACTION = "DISPLAY";

/**
 * The text a `DISPLAY` alarm shows.
 *
 * RFC 5545 §3.6.6 REQUIRES `DESCRIPTION` on a display alarm, so there is no
 * "leave it off" option, and it is a fixed string rather than the event's own
 * title on purpose: the title is stranger-authored on an event that arrived as
 * an invitation, and copying it here would put third-party text into a second
 * property of a resource this server writes. A receiving client shows the
 * event's own summary beside the alert regardless.
 */
const ALARM_DESCRIPTION = "Reminder";

/**
 * Build one `VALARM`, ready to hang on the component that carries it.
 *
 * The trigger is written as a literal `-PT{n}M` string through
 * `addPropertyWithValue`. That was MEASURED against this repository's own
 * `ical.js@2.2.1` rather than assumed: it is byte-identical to constructing an
 * `ICAL.Duration` with `isNegative` and setting that, `getFirstProperty("trigger").type`
 * comes back `"duration"` either way because the library's design table maps
 * `trigger` to that default type, and no `VALUE=` parameter is emitted on either
 * route. The literal is the shorter of two identical answers.
 *
 * **No `RELATED` parameter.** RFC 5545 §3.8.6.3's default is `RELATED=START`,
 * expressed by the parameter's ABSENCE — so emitting it would be a claim the
 * request never made, which is `addParticipants`' own argument for not
 * substituting a default `ROLE`.
 *
 * **A `UID`, and no `X-WR-ALARMUID`.** RFC 9074 §6 sanctions a `UID` on a
 * `VALARM`, ical.js emits it cleanly, and it costs nothing if unnecessary. The
 * `X-` form is claimed to be wanted by iCloud only by secondary sources with no
 * primary Apple documentation, and "an Apple client WRITES a property" does not
 * establish "an Apple client REQUIRES it". An `X-` property this server invents
 * is one every future update has to preserve, so none is written; plan 17-09's
 * read-back answers the question in the data, and if iCloud supplies one of its
 * own then iCloud is supplying what it needs.
 *
 * The identifier is scoped to the ALARM rather than to the event. Two alarms on
 * one event sharing an identifier would be the defect two components sharing a
 * `RECURRENCE-ID` is: a receiving client cannot tell which is which.
 */
export function buildAlarm(spec: AlarmSpec): IcalComponent {
  const alarm = new ICAL.Component("valarm");
  alarm.addPropertyWithValue("action", ALARM_ACTION);
  alarm.addPropertyWithValue("description", ALARM_DESCRIPTION);
  alarm.addPropertyWithValue("uid", `${crypto.randomUUID()}@icloud-mcp`);
  alarm.addPropertyWithValue("trigger", `-PT${spec.minutesBefore}M`);
  return alarm;
}

/**
 * Which of one component's alarms this server can express, and how many it cannot.
 *
 * **The trigger is read as `-duration.toSeconds() / 60` and NEVER as
 * `.minutes`**, and that is the load-bearing line in this function. An alarm
 * another client wrote as one hour before the event parses to a duration whose
 * `.minutes` is ZERO — the library puts the hour in `.hours` and folds nothing —
 * so a reader keyed on that field reports "at the time of the event" for a
 * reminder the user set an hour early, and nothing anywhere raises. It is the
 * same shape of defect the `RFC822.SIZE`-versus-`RFC822` distinction in
 * `./.claude/CLAUDE.md` §5 exists to prevent: a field that looks right and is
 * wrong. `toSeconds()` folds weeks, days, hours, minutes and seconds into one
 * number and is the only safe read. Pinned by the `-PT1H` case in
 * `test/dav-icalendar.test.ts`.
 *
 * **REFUSE rather than round.** Five shapes are counted as unmodelled and have
 * no number reported for them, because a rounded figure would be a claim about
 * the user's reminder that the user never made:
 *
 *   - an absolute `DATE-TIME` trigger, which is anchored to a moment rather than
 *     to the event and moves differently when the event moves;
 *   - a trigger reaching from the `END` rather than the start;
 *   - a trigger AFTER the start, which is a follow-up rather than a reminder;
 *   - a duration that is not whole minutes;
 *   - an `ACTION` this server does not write.
 *
 * An explicit `RELATED=START` IS accepted, and that is the one place this reader
 * looks past a spelling. It is the RFC's own default written out, so it names
 * exactly the alarm `buildAlarm` produces; refusing it would warn a user that
 * this server cannot express a reminder it can reproduce precisely.
 *
 * **What it does NOT see, said plainly because the next reader will ask.** An
 * alarm whose trigger and action are both expressible is reported as modelled
 * even when it carries OTHER properties this server does not write — an
 * `ACKNOWLEDGED`, an `X-` flag, a `RELATED-TO`. Those are lost by a whole-list
 * replacement, and that is what whole-list replacement MEANS (D-01): a caller
 * supplying a list has asked for their list and no other. The unmodelled count
 * is about alarms this server cannot NAME, not about every byte a replacement
 * costs. An update that says nothing about alarms touches none of it.
 */
export function alarmsOf(component: IcalComponent): AlarmReading {
  const modelled: AlarmSpec[] = [];
  let unmodelled = 0;

  for (const alarm of component.getAllSubcomponents("valarm")) {
    const minutes = minutesBeforeOf(alarm);
    if (minutes === null) {
      unmodelled += 1;
      continue;
    }
    modelled.push({ minutesBefore: minutes, action: "display" });
  }

  return { modelled, unmodelled };
}

/**
 * Whole minutes before the start, or null when this server cannot say.
 *
 * `alarmsOf`'s body, extracted so the five refusals read as five named cases
 * rather than as a chain of guards inside a loop. Every one of them returns null
 * and NOT a repaired number; see that function's docstring, which owns the
 * argument for each.
 *
 * The two enumerated values are compared case-INSENSITIVELY through
 * `toUpperCase`, not the locale-aware form. RFC 5545 §3.8.6.1 and §3.8.6.3
 * define them as tokens and a real calendar contains both spellings; the
 * locale-aware fold gives a different answer under a Turkish locale, and the
 * vitest pool inherits the developer's locale while production runs its own —
 * `foldAddress` in `../confirm.ts` declines it for exactly this reason.
 */
function minutesBeforeOf(alarm: IcalComponent): number | null {
  const action = alarm.getFirstPropertyValue("action");
  if (typeof action !== "string") return null;
  if (action.toUpperCase() !== ALARM_ACTION) return null;

  const trigger = alarm.getFirstProperty("trigger");
  if (trigger === null) return null;

  const related = trigger.getParameter("related");
  if (typeof related === "string" && related.toUpperCase() !== "START") {
    return null;
  }

  const value = trigger.getFirstValue();
  // An absolute trigger parses to a TIME rather than a DURATION, so the type
  // test is what separates "fifteen minutes before whenever this event is" from
  // "the third of September at half past one", and the two are different claims.
  if (!(value instanceof ICAL.Duration)) return null;

  const minutes = -value.toSeconds() / 60;
  if (!Number.isInteger(minutes) || minutes < 0) return null;
  return minutes;
}

/**
 * The alarms on the component a patch of these bytes would TARGET.
 *
 * The preview needs this and cannot compute it: it holds the resource as text,
 * and every byte of iCalendar in this project goes through this module. So the
 * component-picking rule lives here, beside the two writers that follow it,
 * rather than being restated at the tool boundary where it could drift.
 *
 * It mirrors what `applyEventChange` and `applyOccurrenceOverride` actually
 * write to, which is the whole point — a diff computed against a component the
 * write will not touch is a diff about nothing:
 *
 *   - **no recurrence identifier** — the one component a non-repeating resource
 *     holds, which is what `applyEventChange` asserts the change over;
 *   - **a named date that already has an override** — that override, which
 *     `applyOccurrenceOverride` modifies in place;
 *   - **a named date with no override yet** — the MASTER, because a new override
 *     starts as a copy of the master and therefore inherits the master's alarms.
 *
 * **Empty rather than a throw for bytes it cannot read.** A resource this module
 * cannot parse has no write path at all — `withParsedResource` raises on the way
 * to every writer — so nothing is agreed to on the strength of this answer. The
 * caught value is not read, on Conventions §4's rule.
 */
export function storedAlarmsOf(
  icsText: string,
  recurrenceId: string | null,
): AlarmReading {
  const empty: AlarmReading = { modelled: [], unmodelled: 0 };

  try {
    return withParsedResource(icsText, (resource) => {
      if (recurrenceId === null) {
        const target = resource.components[0];
        return target === undefined ? empty : alarmsOf(target);
      }

      const existing = resource.components.find(
        (component) => recurrenceIdStringOf(component) === recurrenceId,
      );
      if (existing !== undefined) return alarmsOf(existing);

      return resource.master === null ? empty : alarmsOf(resource.master);
    });
  } catch {
    return empty;
  }
}

/** One person an event invites. Caller-supplied, and neither half is repaired. */
export interface BuildAttendee {
  /** The address, as the caller spelled it. */
  email: string;
  /** The display name, or null to emit no `CN` at all. */
  name: string | null;
}

/**
 * The people an event names: who is inviting, and who is invited.
 *
 * **One object rather than two independent fields, because the two are only
 * meaningful together.** RFC 6638 makes a resource a *scheduling object
 * resource* — the thing iCloud sends invitations for — on the strength of its
 * `ORGANIZER` matching the collection owner, and an `ORGANIZER` with nobody to
 * tell is a claim about the event that no request ever made. Pairing them makes
 * "an organiser and no attendees" unspeakable rather than merely unlikely.
 *
 * `organizer` is a bare address and never a URI: the `mailto:` is added at the
 * emission site, so there is one place that decides the scheme and no caller
 * can supply a different one.
 */
export interface BuildParticipants {
  /**
   * The ACCOUNT'S OWN address, resolved from its calendar-user-address-set.
   *
   * Never a caller-supplied value. `resolveOrganizerAddress` in `./calendar.ts`
   * is the only thing that produces one, it takes no caller input, and the
   * reason is 04-03's decision one protocol over: a caller-supplied From is a
   * caller-supplied identity. Here the consequence is worse than a mislabelled
   * draft — it is an invitation sent under somebody else's name.
   */
  organizer: string;
  /**
   * The people being invited, in the CALLER'S supplied order.
   *
   * Collapsed on the way in by `collapseAttendees`, so this list is the set of
   * people who are actually told and its length is the count a preview reports.
   */
  attendees: readonly BuildAttendee[];
}

/**
 * The participation values every attendee this server writes carries.
 *
 * **Constants rather than parameters, and that is the participation boundary
 * expressed structurally.** There is nowhere for a caller — or for a value read
 * off somebody else's resource — to put a different `PARTSTAT`, so this server
 * cannot change another person's participation status, cannot reply on the
 * user's behalf, and cannot launder an acceptance back through a write. The
 * read side's own T-03-38 note says a list of attendee addresses on a read tool
 * is exactly where a later session would reach for a reply feature; this is
 * that rule held on the write side, where the reaching would land.
 *
 * `NEEDS-ACTION` is the initial value RFC 5545 §3.2.12 defines, and it is the
 * only honest one for a person who has just been asked.
 */
const ATTENDEE_ROLE = "REQ-PARTICIPANT";
const ATTENDEE_PARTSTAT = "NEEDS-ACTION";
const ATTENDEE_RSVP = "TRUE";

/**
 * Fold one address for matching.
 *
 * `toLowerCase` and NOT the locale-aware form, on the precedent `fold` in
 * `./calendar.ts` already set: the locale-aware fold gives a different answer
 * under a Turkish locale, where a dotted capital I folds to a dotless one — and
 * the vitest pool inherits the developer's locale while production runs its own.
 *
 * **No Unicode normalisation.** NFC and NFD are left exactly as the caller sent
 * them, on `canonicalChange`'s rule: normalising a person's own address is a
 * repair, and this project refuses repairs on user-authored text as firmly as it
 * refuses them on stranger-authored text.
 */
function foldAddress(value: string): string {
  return value.toLowerCase();
}

/**
 * Collapse duplicate addresses FIRST-WINS, preserving the caller's order.
 *
 * Three spellings of one address is one recipient, so the resource must carry
 * one `ATTENDEE` and the preview must report a count of one. First-wins keeps
 * the earlier entry's display name, which is the rule this project already
 * chose once for duplicate message headers — choosing it again rather than
 * inventing a second one is the point.
 *
 * **This is written twice on purpose, and the duplication is the lesser
 * evil.** `canonicalChange` in `src/confirm.ts` performs the same collapse on
 * the way into the change hash, and the two cannot share a symbol: that module
 * is deliberately protocol-neutral and may not import from `src/dav/`, while
 * this one is a pure parser that must not acquire a dependency on a
 * confirmation module. What CAN be held is the AGREEMENT between them, and
 * `test/dav-icalendar.test.ts` holds it behaviourally — asserting that the two
 * collapse the same list to the same length and the same addresses, which is
 * the property that survives either side being edited.
 *
 * Order is preserved here and SORTED there, and that difference is deliberate
 * rather than an oversight: the hash sorts so that reordering the same people
 * is the same change, while the resource keeps the order the caller meant
 * because that is what the parse side reads back as document order. Unifying
 * the two is a natural-looking tidy-up that would make a reordering look like a
 * change.
 *
 * Generic over the shape rather than fixed to `BuildAttendee`, so the tool
 * boundary can collapse its own `AttendeeChange` list — the same fold, one
 * implementation — without either type importing the other.
 */
export function collapseAttendees<T extends BuildAttendee>(
  attendees: readonly T[],
): T[] {
  const seen = new Set<string>();
  const collapsed: T[] = [];
  for (const attendee of attendees) {
    const folded = foldAddress(attendee.email);
    if (seen.has(folded)) continue;
    seen.add(folded);
    collapsed.push(attendee);
  }
  return collapsed;
}

/**
 * The two fields that decide how one end of an event is anchored.
 *
 * Named as its own shape rather than taken as a whole `BuildEventInput`, so the
 * occurrence-override builder can hand `anchoredTime` its own change object
 * without either type importing the other. `anchoredTime` reads exactly these
 * two and nothing else, which is what makes the narrowing honest rather than a
 * convenience.
 */
interface TimeAnchor {
  /** The zone the wall clocks are expressed in, or null for an all-day date. */
  tzid: string | null;
  /** True for a date-only event. `tzid` must then be null. */
  allDay: boolean;
}

/** What one event needs before it can be written. */
export interface BuildEventInput extends TimeAnchor {
  /** The title, verbatim. Escaping is the library's job, not this caller's. */
  summary: string;
  /** `YYYY-MM-DDTHH:MM:SS`, read in `tzid`. For `allDay` only the date is used. */
  startLocal: string;
  /** `YYYY-MM-DDTHH:MM:SS`, same reading. */
  endLocal: string;
  /**
   * The zone the two wall clocks are expressed in, or null for an all-day date.
   *
   * Null is the ONLY way to get a resource with no zone. There is deliberately
   * no "just leave the parameter off" path for a timed event: that produces a
   * floating time, which is a different claim and one this server's own reader
   * reports as anchored to nothing.
   */
  tzid: string | null;
  /** True for a date-only event. `tzid` must then be null. */
  allDay: boolean;
  /** Verbatim, or null to omit the property entirely. */
  location: string | null;
  /** Verbatim, or null to omit the property entirely. */
  description: string | null;
  /**
   * Who is inviting and who is invited, or null for an event that reaches
   * nobody.
   *
   * **Null is the only way to get a resource with no scheduling properties.** A
   * resource carrying `ORGANIZER` or `ATTENDEE` is a scheduling object resource
   * that iCloud sends invitations for; a resource that acquired one by accident
   * would invite somebody nobody asked to invite. See the participation-boundary
   * note on `ATTENDEE_PARTSTAT` above.
   *
   * **A CREATE is the only path that reaches this field at all, and that is what
   * makes the boundary structural rather than enforced (D-02).** An UPDATE used
   * to reach it through a rewrite that passed null unconditionally — an override
   * on one writer, which is a guarantee somebody has to keep remembering. Every
   * update patches now, and a patch never CONSTRUCTS a participant: it asserts
   * seven named properties over the component the resource already had, and
   * neither `ORGANIZER` nor `ATTENDEE` is among them. So an attendee list this
   * server READ cannot survive into a resource it WROTE because there is no
   * writer on that path that emits one, not because a writer was told not to.
   *
   * Pinned by "no update path emits an ATTENDEE, whatever the change carries" in
   * `test/dav-tools.test.ts`, which drives every scope with a confirmed change
   * carrying three people and asserts none of them reaches the bytes.
   *
   * An empty `attendees` array is treated as null: nobody is nobody, and an
   * `ORGANIZER` with no recipients is a claim the request never made.
   */
  participants: BuildParticipants | null;
  /**
   * The revision to EMIT — not the one the resource carried (CALW-07).
   *
   * **The builder is told rather than deciding, and that split is the whole
   * defence.** A create passes zero, which RFC 5545 §3.8.7.4 defines as a new
   * event's first revision. Deciding here would mean one function holding both
   * a create's answer and an update's, and the create's is the wrong one
   * whenever a resource already exists.
   *
   * **Like `participants` above, only a CREATE reaches this field now (D-02).**
   * An update patches, and `applyOverrideChange` writes `nextSequence` of the
   * patched component's OWN stored revision — read off the bytes rather than
   * supplied, so a caller cannot reach the wire with a revision it chose. That
   * used to be an override on a rewrite; it is now a property of the only writer
   * there is. Pinned by "takes the revision off the stored component, so a caller
   * cannot choose one" in `test/dav-tools.test.ts`.
   */
  sequence: number;
  /**
   * The reminders to write, or absent for an event that carries none (CALM-01).
   *
   * Absent and an empty array produce the SAME bytes here, and this is the one
   * place in the project where the two legitimately agree: a resource that does
   * not exist yet has no stored alarm for an empty list to remove. The
   * distinction is real on the UPDATE path — see `OverrideChange.alarms`, where
   * absent means leave every stored alarm alone and `[]` means take them all
   * away — and the field is optional on both so the two types read the same at
   * every call site that carries a change between them.
   */
  alarms?: AlarmSpec[];
}

/**
 * The next revision, from the one the fetched resource carried (CALW-07).
 *
 * **Its own named function rather than a `+ 1` at the emission site, because
 * this arithmetic fails SILENTLY.** RFC 5545 §3.8.7.4 uses `SEQUENCE` to tell a
 * receiving client that a newer version of the same event has arrived. A value
 * that goes BACKWARDS raises nothing anywhere — not here, not at iCloud, not in
 * the attendee's client. The update is simply treated as stale and ignored, so
 * the organiser sees the new time and every attendee keeps the old one, and no
 * layer reports a problem. A `+ 1` folded into a builder is one a later edit
 * can lose with nothing going red; a named function with its own cases cannot
 * be lost that quietly.
 *
 * **Null means the property was ABSENT, and absent means zero** — so the first
 * update of a resource that never carried one emits `1`, not `0`. Emitting zero
 * there would be re-asserting the revision the resource already had.
 *
 * Read from the resource, never counted locally and never stored. A
 * locally-tracked revision and a server-side one diverge the first time
 * anything else edits the event, and the divergence is silent in exactly the
 * way above.
 */
export function nextSequence(carried: number | null): number {
  return (carried ?? 0) + 1;
}

/**
 * The revision one parsed resource carries, or null when it carries none.
 *
 * Narrowed to a non-negative integer rather than coerced. The library hands
 * back a union covering every value type the design set knows, and a `SEQUENCE`
 * that is not a whole count is not a revision — reporting absence there is the
 * same refuse-never-repair discipline `textOf` applies to text, and it lands on
 * `nextSequence`'s absent arm, which emits one.
 *
 * Reads the FIRST component. Every caller of this function has already refused
 * a resource with more than one, because a master plus its overrides is a
 * series and a series is not rewritable at all.
 */
export function sequenceOfResource(
  resource: ParsedCalendarResource,
): number | null {
  const component = resource.components[0];
  if (component === undefined) return null;
  return sequenceOfComponent(component);
}

/**
 * The revision ONE component carries, or null when it carries none.
 *
 * `sequenceOfResource`'s body, extracted so the occurrence-override builder can
 * ask the same question of the master and of an existing override — the two
 * answers differ, and an override advanced from the master's revision rather
 * than its own would go backwards the second time the same date is edited.
 */
function sequenceOfComponent(component: IcalComponent): number | null {
  const value = component.getFirstPropertyValue("sequence");
  if (typeof value !== "number") return null;
  if (!Number.isInteger(value) || value < 0) return null;
  return value;
}

/**
 * Build one `VEVENT`, ready to be wrapped and serialised.
 *
 * The UID is minted here rather than taken from the caller, and that is what
 * makes a create NON-IDEMPOTENT: two calls with byte-identical input produce
 * two different identifiers and therefore two different events. That is a
 * property worth stating rather than discovering, and the tool's own
 * description states it.
 *
 * `DTSTAMP` is built from `Date.now()` through the same epoch-anchored
 * construction the range bounds use. That reads an INSTANT rather than a set of
 * local calendar fields, so it carries none of the host-zone dependency the
 * `ical-jsdate` rule bans — the hazard there is a conversion that reads fields
 * in the host machine's zone, not the existence of a clock.
 */
export function buildVEvent(input: BuildEventInput): IcalComponent {
  const vevent = new ICAL.Component("vevent");

  vevent.addPropertyWithValue("uid", `${crypto.randomUUID()}@icloud-mcp`);
  vevent.addPropertyWithValue(
    "dtstamp",
    utcTimeAt(Math.floor(Date.now() / 1000)),
  );
  // The revision this resource claims, HANDED IN rather than decided here. See
  // `BuildEventInput.sequence` and `nextSequence`: a create's zero and a
  // rewrite's stored-value-plus-one are different answers, and a builder that
  // chose would give the create's answer to both.
  vevent.addPropertyWithValue("sequence", input.sequence);
  vevent.addPropertyWithValue("summary", input.summary);
  if (input.location !== null) {
    vevent.addPropertyWithValue("location", input.location);
  }
  if (input.description !== null) {
    vevent.addPropertyWithValue("description", input.description);
  }
  vevent.addProperty(anchoredTime("dtstart", input.startLocal, input));
  vevent.addProperty(anchoredTime("dtend", input.endLocal, input));
  addParticipants(vevent, input.participants);
  // AFTER the participants, so the subcomponent ordering a created resource
  // carries is stable and can be pinned by a byte comparison. A `VALARM` is the
  // only subcomponent a `VEVENT` this server builds ever has, so "after" is a
  // property of the source order rather than a sort.
  setAlarms(vevent, input.alarms);

  return vevent;
}

/**
 * Name the account that is inviting, and the people it is inviting (CALW-06).
 *
 * **Emitting these is what makes iCloud send a real invitation to a real
 * mailbox**, and that is measured rather than inferred: probe P-1 in
 * `05-UAT.md` put an `ATTENDEE` on a resource against the live account and the
 * mail arrived. RFC 6638 has the CALENDAR SERVER generate and deliver the iTIP
 * messages from the stored resource; this Worker opens no submission port and
 * links no mail-sending library, and `./.claude/CLAUDE.md` §2 records the
 * reconciliation on the safety boundary rather than leaving it to be re-derived.
 *
 * **No scheduling-agent parameter is emitted, ever.** The RFC's default is
 * server-side delivery and the default is expressed by the parameter's ABSENCE,
 * so the happy path emits nothing — but the reason there is no unhappy path
 * either is D5-2, settled NEGATIVE by measurement. Probe P-2 set the
 * client-agent form against the live account: iCloud preserved the parameter
 * VERBATIM on the stored resource and mailed the attendee anyway, stamping its
 * own send report onto the same line. Preserved-but-ignored is the worst of the
 * three possible outcomes, because a round trip looks exactly like acceptance —
 * code that set the flag and re-read it to confirm would report suppression
 * working while invitations went out. A control that cannot work must not be
 * offered, so none is, in any spelling.
 *
 * **`ORGANIZER` carries no `CN`.** The account's display name is not something
 * this server has resolved, and inventing one would put a name on an invitation
 * that the account owner never chose. iCloud rewrites the organiser line on the
 * way in regardless (P-1 (d)), replacing the `mailto:` with an opaque principal
 * href — so what matters here is that the ADDRESS matches one of the collection
 * owner's calendar user addresses, which is the only thing RFC 6638 checks.
 *
 * Attendees are emitted in the CALLER'S supplied order after a first-wins
 * collapse, so the resource and the change hash agree about who is on the event
 * even though they disagree about the order — see `collapseAttendees`.
 */
function addParticipants(
  vevent: IcalComponent,
  participants: BuildParticipants | null,
): void {
  if (participants === null) return;

  const attendees = collapseAttendees(participants.attendees);
  // Nobody is nobody. An `ORGANIZER` with no `ATTENDEE` is a scheduling object
  // resource with no recipients, which is a claim about the event that no
  // request made — and it is the shape an empty array would otherwise produce.
  if (attendees.length === 0) return;

  const organizer = new ICAL.Property("organizer", vevent);
  organizer.setValue(`mailto:${participants.organizer}`);
  vevent.addProperty(organizer);

  for (const attendee of attendees) {
    const property = new ICAL.Property("attendee", vevent);
    // `CN` FIRST and only when a name was supplied. Absent means absent, on the
    // parse side's own argument for not substituting a default `ROLE`:
    // publishing a claim the caller never made as though they had made it is
    // worse than an absent parameter.
    if (attendee.name !== null) property.setParameter("cn", attendee.name);
    property.setParameter("role", ATTENDEE_ROLE);
    property.setParameter("partstat", ATTENDEE_PARTSTAT);
    property.setParameter("rsvp", ATTENDEE_RSVP);
    property.setValue(`mailto:${attendee.email}`);
    vevent.addProperty(property);
  }
}

/**
 * One end of an event, anchored the way the format anchors it.
 *
 * The zone travels as a PARAMETER on the property and the wall clock is parsed
 * from its own string with NO property handed to the parser. That second half
 * is the load-bearing one: passing the property would make the library walk up
 * the component tree for a matching `VTIMEZONE` and then fall through to the
 * process-global service when it found none — which is the registration this
 * whole half of the module is written to avoid. With no property there is no
 * lookup, the value stays a plain wall clock, and the `TZID` parameter beside
 * it is what says how to read it.
 */
function anchoredTime(
  name: string,
  wallClock: string,
  input: TimeAnchor,
): IcalProperty {
  const property = new ICAL.Property(name);

  if (input.allDay || input.tzid === null) {
    // A date is anchored to nothing by definition, so it takes no zone
    // parameter and needs no definition in the resource. `VALUE=DATE` is
    // emitted by the serialiser, from the value's own type.
    property.setValue(ICAL.Time.fromDateString(wallClock.slice(0, 10)));
    return property;
  }

  property.setParameter("tzid", input.tzid);
  property.setValue(ICAL.Time.fromString(wallClock, undefined));
  return property;
}

/**
 * Wrap one `VEVENT` in a `VCALENDAR` and hand back the bytes to write.
 *
 * **No `METHOD` property.** RFC 4791 §4.1 forbids one on a stored calendar
 * object resource; tsdav's own documentation example carries `METHOD:PUBLISH`,
 * and copying it ships a technically-invalid resource to a server that may or
 * may not object today.
 *
 * The `VTIMEZONE` is added as a PARSED COMPONENT rather than as spliced text,
 * so the whole resource goes through one serialiser and cannot end up with two
 * different ideas of folding or framing.
 *
 * The trailing terminator is added here because `Component#toString()` does not
 * emit one after `END:VCALENDAR`. Every resource this project reads is
 * terminated, RFC 5545 delimits lines rather than separating them, and a
 * consumer that splits on CRLF should not have to special-case the last line.
 */
export function serializeCalendarResource(
  vevent: IcalComponent,
  tzid: string | null,
): string {
  const vcalendar = new ICAL.Component("vcalendar");
  vcalendar.addPropertyWithValue("version", "2.0");
  vcalendar.addPropertyWithValue("prodid", PRODID);

  if (tzid !== null) {
    const definition = zoneDefinitionOf(tzid);
    // Unreachable through `createEvent`, which refuses an unknown zone before
    // anything is built. Kept because the alternative is a non-null assertion,
    // and an assertion is a claim about a caller this function cannot see.
    if (definition === null) throw new DavConnectError();
    vcalendar.addSubcomponent(new ICAL.Component(ICAL.parse(definition)));
  }

  vcalendar.addSubcomponent(vevent);

  return `${vcalendar.toString()}\r\n`;
}

// ---------------------------------------------------------------------------
// The RECURRENCE half of the write side (CALW-02, plan 05-10)
//
// A recurring event is ONE DAV resource holding the master rule and every
// override, and a write rewrites all of it. So an occurrence-scoped edit and a
// series-scoped edit differ only in what the code chose to touch, and "it only
// changed one Tuesday" is a property of this file rather than of the protocol.
//
// Two properties hold this half together and both are stated once here.
//
// **The master is READ and never written.** Every function below either reads
// the master or writes to a CLONE, and `applyOccurrenceOverride` returns clones
// of every component so that the parsed resource it was handed is provably
// unchanged afterwards. That is what makes the byte-identity assertion in
// `test/dav-icalendar.test.ts` a measurement rather than a claim about intent.
//
// **Nothing here touches `ICAL.TimezoneService`.** The zone a recurrence
// identifier is expressed in comes from the MASTER'S OWN `TZID` parameter, read
// as text and copied onto the new property; the identifier's value comes from
// the master's own iterator, which yields times already carrying the master's
// zone. There is nothing to resolve and therefore nothing to register — the
// same claim the build side above makes, for the same reason (Pitfall 7: a
// registration left behind by a write path re-anchors that identifier for every
// later request in the isolate).
// ---------------------------------------------------------------------------

/**
 * How much of a series a write reaches. There is deliberately no fourth value
 * and no default.
 *
 * **Named for what the USER means, never for the RFC's spelling.** A model
 * reading a protocol-level parameter name has no way to know what it does; a
 * model reading these three does. That is D5-2's naming rule applied to a second
 * control, and it is the reason `RANGE=THISANDFUTURE` — the wire form probe P-8
 * measured — is spelled `this-and-future` here.
 *
 * FROZEN and exported for the reason `DAV_KIND_LETTERS` is exported: the input
 * schema and the tests both compare against the SHIPPED list rather than a copy,
 * so a fourth value added later cannot leave one of them agreeing with itself.
 * `Object.freeze` rather than `as const` alone, because `as const` is a
 * compile-time claim and a frozen array is a runtime one — and the thing being
 * protected is a published tool-input vocabulary.
 */
export const WRITE_SCOPES = Object.freeze([
  "occurrence",
  "this-and-future",
  "series",
] as const);

/** One of the three values `WRITE_SCOPES` admits. */
export type WriteScope = (typeof WRITE_SCOPES)[number];

/** Whether a string is one of the three shipped scopes. */
export function isWriteScope(value: string | null): value is WriteScope {
  return value !== null && (WRITE_SCOPES as readonly string[]).includes(value);
}

/**
 * What a preview says instead of a number when the series has no reachable end.
 *
 * **A constant rather than a large number or a null**, because the three
 * readings are different claims. A number would say "this many move", which
 * would be false. A null would say "this server has no answer", which is weaker
 * than the truth. This says the rule runs on past anything this server will
 * walk, which is what a caller needs to know before agreeing to move all of it.
 *
 * It is this server's own word in its own closed vocabulary, so it rides in the
 * TRUSTED half of a preview beside the numbers it stands in for.
 */
export const UNBOUNDED_OCCURRENCES = "unbounded";

/** How many occurrences a resource produces, counted rather than estimated. */
export interface OccurrenceCounts {
  /** Every slot the rule produces, when the walk reached the end. */
  total: number;
  /** The named slot and every slot after it, when the walk reached the end. */
  fromNamed: number;
  /**
   * False when a cap stopped the walk before the rule ran out.
   *
   * The two numbers above are then PARTIAL and must not be published as
   * answers — `UNBOUNDED_OCCURRENCES` is what gets published instead. They are
   * still returned rather than zeroed, because a caller that wants to say "at
   * least this many" has the figure and a caller that does not can ignore it.
   */
  bounded: boolean;
}

/**
 * Whether this resource is a series rather than a single event.
 *
 * **The question a write has to ask BEFORE it asks anything else**, because it
 * is what decides whether a scope is required. Four properties and one
 * structural fact make a resource a series, and all five are checked: a rule, a
 * date list, an exclusion list, a recurrence identifier on any component, or
 * simply more than one component — a master plus its overrides is a series
 * whether or not this particular component carries the rule.
 *
 * `exdate` counts even though it only ever appears beside a rule. A resource
 * carrying one without a rule is malformed rather than single, and treating a
 * malformed resource as the degenerate case is how a write reaches more of it
 * than the caller meant.
 */
export function isRecurringResource(resource: ParsedCalendarResource): boolean {
  if (resource.components.length > 1) return true;
  for (const component of resource.components) {
    for (const name of ["rrule", "rdate", "exdate", "recurrence-id"]) {
      if (component.hasProperty(name)) return true;
    }
  }
  return false;
}

/**
 * Count what a series produces, so a preview can promise a number.
 *
 * **The number a preview states must be the number the write produces**, which
 * is why this is a real walk rather than an arithmetic guess off the rule. A
 * `COUNT=4` rule is easy to read off; a `FREQ=WEEKLY;BYDAY=MO,WE;UNTIL=...` with
 * an `EXDATE` is not, and a guess that is usually right is the shape of failure
 * this whole plan exists to prevent.
 *
 * Bounded by the SAME two caps every other walk in this module uses, and on
 * trip it reports `bounded: false` rather than raising — the caller publishes
 * `UNBOUNDED_OCCURRENCES` instead of a partial figure. That is the disposition
 * `truncated` already has one function up: a partial answer labelled as partial
 * is more useful than an error, and a partial answer published as a total is
 * worse than either.
 *
 * `recurrenceId` is compared in WIRE form, which is what the opaque identifier
 * carries — the same comparison `findOccurrence` makes, for the same reason.
 *
 * A MASTERLESS resource is a finite component list already in memory, so it is
 * counted in document order with no walk at all and reports `bounded: true`.
 */
export function countOccurrences(
  resource: ParsedCalendarResource,
  recurrenceId: string | null,
  cap: number = MAX_EXPANDED_OCCURRENCES,
  maxSteps: number = MAX_ITERATOR_STEPS,
): OccurrenceCounts {
  if (resource.master === null) {
    const total = resource.components.length;
    const index = resource.components.findIndex(
      (component) => recurrenceIdStringOf(component) === recurrenceId,
    );
    return {
      total,
      fromNamed: index < 0 ? 0 : total - index,
      bounded: true,
    };
  }

  const iterator = new ICAL.Event(resource.master).iterator();
  let total = 0;
  let fromNamed = 0;
  let steps = 0;
  let seen = false;

  let next: IcalTime | null | undefined = iterator.next();
  while (next) {
    steps += 1;
    if (steps > maxSteps || total >= cap) {
      return { total, fromNamed, bounded: false };
    }
    total += 1;
    if (!seen && next.toICALString() === recurrenceId) seen = true;
    if (seen) fromNamed += 1;
    next = iterator.next();
  }

  return { total, fromNamed, bounded: true };
}

/**
 * How far forward one override reaches: this date only, or this date onward.
 *
 * **Two values rather than a boolean, because the call sites read as sentences
 * and a bare `true` at one of them would say nothing about which direction it
 * reaches.** The spelling deliberately matches `WRITE_SCOPES`' own middle value,
 * so the scope a caller asked for and the parameter that expresses it are one
 * word rather than a mapping somebody has to remember.
 */
export type OverrideRange = "this-only" | "this-and-future";

/** What an occurrence-scoped edit asserts about the one date it reaches. */
export interface OverrideChange extends TimeAnchor {
  /** The title, verbatim. Escaping is the library's job. */
  summary: string;
  /** `YYYY-MM-DDTHH:MM:SS`, read in `tzid`. For `allDay` only the date is used. */
  startLocal: string;
  /** `YYYY-MM-DDTHH:MM:SS`, same reading. */
  endLocal: string;
  /** Verbatim, or null to REMOVE the property from the override. */
  location: string | null;
  /** Verbatim, or null to REMOVE the property from the override. */
  description: string | null;
  /**
   * The reminders to assert, or ABSENT to leave every stored one alone (D-04).
   *
   * **Absent and `[]` are different requests, and the difference is in the TYPE
   * rather than in a convention somebody remembers.** An absent key touches no
   * `VALARM` at all, so an update that says nothing about reminders keeps the
   * one the user set — including one this server cannot express. An explicit
   * empty array removes every `VALARM` on the component. That is `setOrRemove`'s
   * absent-versus-null pattern one line up, applied to a list: the same claim the
   * tool boundary makes about `location` and `description`, made about alarms.
   *
   * **There is deliberately no `removeAlarms` flag.** A second way to say the
   * same thing is a second thing to keep consistent, and the two would disagree
   * the first time somebody set both.
   *
   * A supplied list replaces the WHOLE list. See `AlarmSpec`, which owns the
   * argument for why there is no per-entry edit.
   */
  alarms?: AlarmSpec[];
}

/**
 * Move ONE occurrence of a series, and leave every other component alone.
 *
 * ## The shape, and it is a MEASUREMENT rather than a reading of the RFC
 *
 * Probe P-7 in `05-UAT.md` put a master and a `RECURRENCE-ID` override in ONE
 * resource against the live account on 2026-08-22. Verbatim, from its recorded
 * answer:
 *
 * > **ACCEPTED. The master-plus-override-in-one-resource shape works, and this
 * > server already reads it correctly.**
 * >
 * > ```
 * > create weekly COUNT=4 series          -> 201
 * > PUT master + RECURRENCE-ID override   -> 204
 * > ```
 * >
 * > The read-back is **byte-identical to what was sent** — both `VEVENT`s
 * > present, same order, no rewrite.
 *
 * So iCloud creates no second resource and rewrites nothing, and this function
 * must not create one either: two resources for one series is a shape every
 * other client on the account reads as two events.
 *
 * ## What it returns, and why every component is a clone
 *
 * The component list to serialise, with the untouched components CLONED rather
 * than passed through. Cloning costs a JSON round trip per component and buys
 * the property this whole plan turns on: the parsed resource handed in is
 * provably unchanged afterwards, so `resource.master` serialises to the same
 * bytes before and after the call. A function that returned the caller's own
 * objects would make that assertion pass by aliasing rather than by restraint.
 *
 * ## Modify in place, never add a second
 *
 * A component already carrying the target recurrence identifier is MODIFIED. Two
 * components carrying the same identifier is a resource no receiving client can
 * read correctly, and the failure mode is the worst kind: different clients pick
 * different ones, so the user's phone and the user's laptop disagree about when
 * the meeting is and neither reports a problem.
 *
 * ## Inheriting, which is the half that is easy to get wrong
 *
 * A new override starts as a COPY of the master and then has the change applied
 * to it. An override carrying only the fields that changed is a valid iCalendar
 * component and a broken event — a receiving client shows an occurrence with no
 * title. Everything the change does not name is inherited: the location it did
 * not move, the description it did not rewrite, the `VALARM` the user set, the
 * `X-` property somebody's client wrote.
 *
 * The four recurrence properties are the deliberate exception. A copy that kept
 * the master's `RRULE` would be an override that is itself a series, which is
 * the second way to make one resource mean two different things.
 *
 * ## Null, and why it is not a throw
 *
 * `null` means the series does not produce that slot — the organiser excluded
 * the date, or changed the rule, or the identifier names nothing in this series
 * at all. A throw here would have to pick an error category for a fact about
 * bytes already in hand, and this module deliberately raises only for a body it
 * cannot read at all. The caller maps it to not-found, which is the same answer
 * `findOccurrence` gives for the same condition.
 *
 * ## `range`, and the form that was NOT built
 *
 * `"this-and-future"` marks the override as reaching this date and every date
 * after it, instead of this date alone. It is ONE conditional write of ONE
 * resource — the same shape as an ordinary override, with one parameter added.
 *
 * The alternative was a series SPLIT: bound the original at the last unchanged
 * date and create a SECOND resource carrying the changed series from the chosen
 * date onward. Two conditional writes, a new resource identifier, and an event
 * id the caller already holds for a post-split date that stops resolving.
 * **That form was not built, and the reason is a measurement rather than a
 * preference.** Probe P-8 half B in `05-UAT.md` put this exact override on the
 * live account on 2026-08-22. Verbatim, from its recorded answer:
 *
 * > **`RANGE=THISANDFUTURE` is APPLIED FROM THAT OCCURRENCE ONWARD — but by
 * > THIS SERVER, not by iCloud.**
 * >
 * > | Occurrence | startLocal | isOverride |
 * > |---|---|---|
 * > | 2026-09-01 | 15:00 | false |
 * > | 2026-09-08 | 15:00 | false |
 * > | 2026-09-15 | **17:00** | **true** |
 * > | 2026-09-22 | **17:00** | **true** |
 * >
 * > The raw `GET` of the stored resource returns **exactly the two components
 * > that were sent**, with `RANGE=THISANDFUTURE` preserved verbatim on the
 * > `RECURRENCE-ID` line. iCloud created no second override for 2026-09-22 and
 * > rewrote nothing.
 * >
 * > **So iCloud is a passive store for this construct. The `THISANDFUTURE`
 * > semantics in the table above are produced entirely by THIS SERVER's own
 * > expansion in `src/dav/icalendar.ts`.** iCloud neither honours nor rejects
 * > the parameter — it round-trips it and leaves interpretation to the client.
 *
 * **The last paragraph is the half that matters, and it is why this file also
 * owns the behaviour.** The bytes going out are accepted and stored unchanged,
 * so no server-side check will ever notice if the expansion above this function
 * stops applying them. A regression here is silent on the account and visible
 * only in `expandOccurrences`, which is why `test/dav-icalendar.test.ts` asserts
 * the LATER occurrences move rather than only asserting the parameter is
 * written.
 *
 * **Two limits of that behaviour, both real and neither claimed away.** A date
 * carrying its OWN override keeps it: a direct exception outranks a ranged one,
 * so an individually-edited later date does not move, and the caller is told how
 * many such dates there are rather than left to notice. And what other clients
 * do with the parameter is NOT established — interpretation is client-side and
 * iCloud takes no position, so nothing here may claim cross-client agreement.
 */
export function applyOccurrenceOverride(
  resource: ParsedCalendarResource,
  recurrenceId: string,
  change: OverrideChange,
  range: OverrideRange = "this-only",
): IcalComponent[] | null {
  const components = resource.components.map(cloneComponent);

  // The EXISTING override first, and by direct comparison rather than by
  // walking the rule. An override whose identifier the rule no longer produces
  // is still a component of this resource, and editing it is still the right
  // answer to "change that date" — the iterator would never reach it.
  const existing = components.findIndex(
    (component) => recurrenceIdStringOf(component) === recurrenceId,
  );
  if (existing >= 0) {
    applyOverrideChange(
      components[existing]!,
      change,
      nextSequence(sequenceOfComponent(components[existing]!)),
    );
    // The reach is ASSERTED on the existing component rather than left as it
    // was, in both directions. An override that already reached forward and is
    // now being edited for one date alone must stop reaching, and one that
    // reached one date must start — otherwise the parameter the caller supplied
    // and the parameter on the wire describe two different requests.
    //
    // **This branch is also the whole of the masterless case**, and it needs no
    // master at all: the target component is already there, its own revision is
    // read off itself, and `applyOverrideChange` builds both ends from the
    // change. Nothing below this line is reached for a resource carrying only
    // overrides — see `dropOverride`, which is that shape's other operation.
    applyRange(components[existing]!, range);
    return components;
  }

  const master = resource.master;
  if (master === null) return null;

  const slot = slotOf(master, recurrenceId);
  if (slot === null) return null;

  const override = cloneComponent(master);
  // The four that would make an override into a series of its own. Everything
  // else the master carried is inherited on purpose — see the docstring.
  for (const name of ["rrule", "rdate", "exdate", "recurrence-id"]) {
    override.removeAllProperties(name);
  }
  override.addProperty(recurrenceIdProperty(master, slot, range));
  applyOverrideChange(override, change, nextSequence(sequenceOfComponent(master)));

  components.push(override);
  return components;
}

/**
 * Change the ONE event a resource holds, and leave every other byte of it alone.
 *
 * ## What it is for, and why `applyOccurrenceOverride` above could not do it
 *
 * That function moves one date OF A SERIES: it needs a recurrence identifier, a
 * master to inherit from, and a slot the rule actually produces. A one-off event
 * has none of those. So this is its non-recurring sibling — the same patch
 * discipline applied to the single component a non-repeating resource carries.
 *
 * The subject is the resource iCloud REWROTE on the way in. Probe P-1 (d)
 * measured what an attendee-carrying `PUT` comes back as: the organiser's
 * `mailto:` replaced by an opaque per-account principal href, `SCHEDULE-STATUS`
 * stamped onto every attendee, `RSVP` dropped, `DTSTAMP` rewritten. Every one of
 * those is a value only iCloud could have produced, and every one of them is
 * lost by a rebuild — which is why an invited event shipped REFUSED from 05-06
 * until this function existed to write it another way.
 *
 * Three things survive here that a rebuild destroys, and the third is the one
 * 05-09 named that nobody had before it:
 *
 *   - the `ORGANIZER` line, parameters and opaque value intact, so the identity
 *     iCloud assigned to the meeting is still the meeting's identity;
 *   - every `SCHEDULE-STATUS` parameter, which is the ONLY evidence this server
 *     has that iCloud said it told anybody;
 *   - every `PARTSTAT`, so an attendee who has already ACCEPTED stays accepted.
 *     A rebuild does not merely fail to carry that forward — it emits
 *     `NEEDS-ACTION`, which ERASES a reply the organiser is relying on.
 *
 * ## One plain event, and null for anything else
 *
 * The test is `isRecurringResource`, which is the same question the tool
 * boundary asks before it decides whether a scope is required — so a resource
 * this refuses is exactly a resource that would have been asked for one. Three
 * shapes fall out of it and each would break differently:
 *
 *   - **A master plus overrides.** One resource holding several events, so "the
 *     event this resource holds" is not a thing it has, and the change would
 *     land on whichever component happened to be first.
 *     `applyOccurrenceOverride` is that shape's operation and it takes the
 *     identifier that says which date is meant.
 *   - **A lone master carrying a rule.** One component, so a bare count check
 *     admits it — and this is the dangerous one, because the result LOOKS
 *     correct. Moving the master's `DTSTART` moves the whole series and ORPHANS
 *     every override stored against the old slots, which is precisely why
 *     `update:series` is refused by name at the tool boundary. A guard that
 *     counted components would have let it through.
 *   - **A lone override.** One edited date of a series whose master lives
 *     somewhere else.
 *
 * Refusing rather than guessing is the whole of the difference. Unreachable
 * through the shipped tools — the tool boundary reads `EventWithEtag.isRecurring`
 * and refuses all three before a scopeless confirmation is minted, either by
 * requiring a scope or, for `series`, by the one arm of `buildPreview`'s blocker
 * that D-02's collapse deliberately kept — and asserted directly for that reason,
 * because a guard nothing can reach is invisible to every assertion around it and
 * the day something CAN reach it is the day it has to already work.
 *
 * ## The revision, and where it comes from
 *
 * `nextSequence` of the component's OWN stored revision, which is
 * `applyOccurrenceOverride`'s rule applied to the only component there is. A
 * revision that goes backwards makes every other client treat the update as
 * stale and ignore it, and it raises nothing anywhere — not here, not at iCloud,
 * not in the receiving client.
 */
export function applyEventChange(
  resource: ParsedCalendarResource,
  change: OverrideChange,
): IcalComponent[] | null {
  // The count and the four recurrence properties in one question, so a LONE
  // MASTER carrying a rule is refused alongside the two shapes a count check
  // would already have caught. See the docstring: that one is the shape whose
  // rewrite looks correct and orphans every override in the series.
  if (isRecurringResource(resource)) return null;

  const components = resource.components.map(cloneComponent);
  // A resource with no `VEVENT` at all. `isRecurringResource` answers false for
  // it — correctly, since nothing there repeats — so it is refused here rather
  // than through a non-null assertion, which would be a claim about a body this
  // function cannot see.
  const target = components[0];
  if (target === undefined) return null;

  applyOverrideChange(target, change, nextSequence(sequenceOfComponent(target)));
  return components;
}

/**
 * Wrap a patched component list back up as the resource to write.
 *
 * **The wrapper is CLONED from the resource's own rather than built from a
 * template**, which is the whole difference between a patch and the rebuild this
 * project retired in D-02. Every `VTIMEZONE` the resource defined survives
 * byte-for-byte, as does its own `PRODID`, its `CALSCALE`, and anything else a
 * client put at the calendar level. A rebuild dropped all of it, which is why it
 * had to REFUSE a resource carrying anything it could not reproduce — and why a
 * patch needs no refusal at all. That is the whole of CALM-03: the guarantee is a
 * property of the writer rather than an allow-list somebody maintains.
 *
 * The zone definition is added only when the resource does not ALREADY define
 * that identifier. Adding a second `VTIMEZONE` for a zone the resource already
 * describes would leave two definitions of one name in one resource, and RFC
 * 5545 gives no rule for which wins.
 *
 * The `DavConnectError` on an unknown zone is unreachable through the tool
 * boundary, which refuses a zone outside `VTIMEZONE_ALLOWLIST` before any
 * confirmation is minted. Kept for `serializeCalendarResource`'s own reason: the
 * alternative is a non-null assertion, and an assertion is a claim about a
 * caller this function cannot see.
 */
export function serializeOccurrenceResource(
  resource: ParsedCalendarResource,
  components: IcalComponent[],
  tzid: string | null,
): string {
  const vcalendar = cloneComponent(resource.vcalendar);
  vcalendar.removeAllSubcomponents("vevent");
  for (const component of components) vcalendar.addSubcomponent(component);

  if (tzid !== null && !resource.definedTzids.includes(tzid)) {
    const definition = zoneDefinitionOf(tzid);
    if (definition === null) throw new DavConnectError();
    vcalendar.addSubcomponent(new ICAL.Component(ICAL.parse(definition)));
  }

  return `${vcalendar.toString()}\r\n`;
}

// ---------------------------------------------------------------------------
// Answering an invitation — the one patch that must NOT look like an edit
//
// Every other writer in this module is an EDIT of the event: it asserts new
// values over one component and advances the revision, because a change nobody
// revised is a change every other client ignores. An answer is the opposite
// case. It is the attendee saying yes or no to somebody else's meeting, and the
// meeting is not theirs to revise. So this patch changes two parameters on the
// user's own attendee line and NOTHING else: no SEQUENCE, no DTSTAMP, no other
// attendee's line, no other property. D-07 decided that, and plan 18-01
// measured on the live account that iCloud stores exactly the bytes such a
// patch writes.
//
// Pure and socket-free, like everything else here. Which addresses are the
// user's is decided by the caller from the signed-in principal's own server
// answer; nothing in this section reads a caller's claim about who they are.
// ---------------------------------------------------------------------------

/**
 * The three answers a user can give, in the protocol's own spelling.
 *
 * Closed on purpose. RFC 5545 admits more PARTSTAT values (`DELEGATED`, an
 * `X-` value), and none of them is a thing this server lets a caller say. The
 * tool boundary maps its own three lowercase words onto these three.
 */
export type ReplyAnswer = "ACCEPTED" | "DECLINED" | "TENTATIVE";

/** The URI scheme an address a person receives mail at carries. */
const MAILTO_PREFIX = "mailto:";

/**
 * Whether one calendar-user address on a line is one of the user's own.
 *
 * **Three arms, and each one was measured rather than assumed (18-01).**
 *
 * - A `mailto:` value, folded. Case in an address is not the user's to
 *   control; a server or a client may write `MAILTO:` or an upper-case domain.
 * - The `EMAIL` parameter, folded, against the address part of a `mailto:` in
 *   the set. **This is the arm a real iCloud invitation needs.** On an
 *   invitation iCloud itself delivered, the user's line carries an opaque
 *   principal path as its value and the address ONLY in `EMAIL=`. A matcher
 *   that read the value alone would call the user a stranger on their own
 *   invitation. **Consulted only when the value is NOT a `mailto:`**
 *   (18-REVIEW WR-01). A line whose value is a `mailto:` already says who it
 *   is, and that is the whole answer. Otherwise an organiser could write the
 *   user's address in `EMAIL=` on Bob's `mailto:` line, leave the user's own
 *   line out, and have the user's answer written onto Bob's line. 18-01 only
 *   ever measured `EMAIL=` beside an opaque path, so this narrows nothing
 *   that was measured.
 * - Any other value, EXACTLY. A principal path or a `urn:uuid:` form is an
 *   opaque identifier, and folding one would be this function inventing an
 *   equivalence the server never declared. The measured line was a relative
 *   path, the same form the account's own set advertises, so no path-versus-URL
 *   comparison is attempted either.
 *
 * `addresses` is the account's calendar-user-address-set exactly as its own
 * principal answered it. Nothing a caller supplied can reach it, and nothing
 * the stored event says about itself can either — this function only ASKS
 * whether a stranger-written value names one of them.
 */
export function isOwnAddress(
  value: string | null,
  emailParameter: string | null,
  addresses: readonly string[],
): boolean {
  const foldedValue = value === null ? null : value.toLowerCase();
  const valueIsMailto = foldedValue !== null && foldedValue.startsWith(MAILTO_PREFIX);
  // Never read beside a mailto value: see the second arm above.
  const foldedEmail =
    valueIsMailto || emailParameter === null || emailParameter.length === 0
      ? null
      : emailParameter.toLowerCase();

  for (const address of addresses) {
    if (address.length === 0) continue;
    const folded = address.toLowerCase();
    if (folded.startsWith(MAILTO_PREFIX)) {
      if (foldedValue !== null && foldedValue === folded) return true;
      const part = folded.slice(MAILTO_PREFIX.length);
      if (foldedEmail !== null && part.length > 0 && foldedEmail === part) {
        return true;
      }
    } else if (value !== null && value === address) {
      return true;
    }
  }
  return false;
}

/** One property's calendar-user address, as the string the line carries. */
function calAddressOf(property: IcalProperty): string | null {
  const value = property.getFirstValue();
  return typeof value === "string" ? value : null;
}

/** Whether one `ORGANIZER` or `ATTENDEE` property names the user. */
function namesUser(property: IcalProperty, addresses: readonly string[]): boolean {
  return isOwnAddress(
    calAddressOf(property),
    firstParameter(property, "email"),
    addresses,
  );
}

/**
 * What answering an invitation would do, decided before anything is written.
 *
 * One arm that carries the patched components and four refusals, on
 * `SeriesNarrowing`'s pattern: the caller dispatches on the arm and cannot
 * reach a component list on a refusal.
 *
 * - `not-invited`: no line on this resource is the user's, or the line that is
 *   sits on a component with no organiser — which is an event, not an
 *   invitation.
 * - `organiser`: the user organises this meeting. An organiser does not answer
 *   their own invitation, and a forged `ORGANIZER` that happens to carry the
 *   user's address is refused the same way (T-18-08).
 * - `ambiguous`: two of the user's addresses sit on one component. Which one
 *   the organiser is waiting on is not a question this server can answer, so it
 *   refuses rather than choosing.
 * - `unchanged`: the stored answer already IS the requested one. Zero writes is
 *   the honest cost of a request that changes nothing (D-15).
 */
export type ReplyPlan =
  | {
      kind: "ok";
      /** The component list to serialise. Every entry is a clone. */
      components: IcalComponent[];
    }
  | { kind: "not-invited" }
  | { kind: "organiser" }
  | { kind: "ambiguous" }
  | { kind: "unchanged" };

/** The four arms that carry no payload, allocated once. */
const REPLY_NOT_INVITED: ReplyPlan = Object.freeze({ kind: "not-invited" } as const);
const REPLY_ORGANISER: ReplyPlan = Object.freeze({ kind: "organiser" } as const);
const REPLY_AMBIGUOUS: ReplyPlan = Object.freeze({ kind: "ambiguous" } as const);
const REPLY_UNCHANGED: ReplyPlan = Object.freeze({ kind: "unchanged" } as const);

/**
 * Set the user's own answer on every component that carries their line.
 *
 * **Clone first, then patch the clones**, which is `applyEventChange`'s shape:
 * the parsed resource is never mutated, so a caller can serialise it twice and
 * get the same answer both times.
 *
 * **Every component, not the first one.** A master and its overrides each
 * carry their own copy of the attendee list, and an answer set on the master
 * alone would leave every edited occurrence still waiting for a reply the user
 * already gave.
 *
 * **What it writes, exhaustively: on each of the user's own attendee lines,
 * `PARTSTAT` becomes the answer and `RSVP` goes.** `RSVP=TRUE` is the organiser
 * asking for a reply, and a line that has replied no longer asks. Nothing else
 * is touched. It never calls the override writer, because that writer advances
 * SEQUENCE and DTSTAMP, and an attendee who bumps the organiser's revision is
 * editing a meeting that is not theirs (D-07). 18-01 measured that iCloud
 * stores these bytes unchanged and that SEQUENCE stays where it was.
 *
 * The `X-APPLE-NEEDS-REPLY` flag an imported copy carries is left standing too.
 * The owner decided that on 2026-09-26 (18-UAT.md, `device_flag_decision`), so
 * D-07 has no exception here.
 *
 * The organiser check runs FIRST, across every component, so a resource that
 * names the user as both organiser and attendee is refused as the organiser's
 * rather than answered.
 */
export function applyReply(
  resource: ParsedCalendarResource,
  addresses: readonly string[],
  answer: ReplyAnswer,
): ReplyPlan {
  const components = resource.components.map(cloneComponent);

  for (const component of components) {
    for (const organizer of component.getAllProperties("organizer")) {
      if (namesUser(organizer, addresses)) return REPLY_ORGANISER;
    }
  }

  const matched: IcalProperty[] = [];
  for (const component of components) {
    const own = component
      .getAllProperties("attendee")
      .filter((attendee) => namesUser(attendee, addresses));
    if (own.length > 1) return REPLY_AMBIGUOUS;
    if (own.length === 0) continue;
    // A line of the user's on a component nobody organises is an event the user
    // is listed on, not an invitation somebody is waiting on an answer to.
    if (component.getAllProperties("organizer").length === 0) {
      return REPLY_NOT_INVITED;
    }
    matched.push(own[0]);
  }
  if (matched.length === 0) return REPLY_NOT_INVITED;

  const already = matched.every(
    (line) => firstParameter(line, "partstat")?.toUpperCase() === answer,
  );
  if (already) return REPLY_UNCHANGED;

  for (const line of matched) {
    line.setParameter("partstat", answer);
    line.removeParameter("rsvp");
  }
  return { kind: "ok", components };
}

/**
 * What the stored bytes say about whether iCloud will tell the organiser.
 *
 * Three literals, and the third is the one that matters. See
 * `invitationFactsOf` for how each is read.
 *
 * - `scheduling-object`: iCloud holds the organiser relationship. 18-01
 *   measured a PARTSTAT-only write on one of these reaching the organiser.
 * - `imported-copy`: a `.ics` somebody opened into Calendar. 18-01 measured the
 *   same write on one of these reaching nobody.
 * - `undetermined`: the bytes do not say. The tool layer maps this to "may tell
 *   the organiser" and never to "nobody is told", because the second is the one
 *   claim that would let a reply go out that the user was told would not.
 */
export type SchedulingEvidence =
  | "scheduling-object"
  | "imported-copy"
  | "undetermined";

/**
 * Who organises an invitation, as the line carries it (D-12).
 *
 * Two fields rather than one display string, because "the organiser's address
 * is unknown" is a fact the preview states in its own words, and a single
 * string that fell back from the name to the address would have erased it.
 */
export interface InvitationOrganizer {
  /** The `CN`, verbatim and untrusted. Null when absent or empty. */
  name: string | null;
  /**
   * The address the reply would go to: the `mailto:` value, else the `EMAIL`
   * parameter, else null. Verbatim and untrusted. 18-01 measured a genuine
   * iCloud invitation whose organiser value is an opaque principal path with
   * the address only in `EMAIL=`, which is why the parameter is read too.
   */
  address: string | null;
}

/** One other person on an invitation, verbatim. Every field untrusted. */
export interface InvitationAttendee {
  /** The `CN`. Null when absent. */
  name: string | null;
  /** The `mailto:` address, else the `EMAIL` parameter, else null. */
  email: string | null;
  /** The raw `PARTSTAT`. The tool layer matches it against a closed table. */
  partstat: string | null;
}

/** What a preview needs to know about one invitation, read in one parse. */
export interface InvitationFacts {
  /**
   * Who organises it: the first `ORGANIZER` on the resource, or both fields
   * null when there is none. Untrusted and verbatim.
   */
  organizer: InvitationOrganizer;
  /**
   * The raw `PARTSTAT` on the user's own line, on the first component carrying
   * one, or null. Untrusted and verbatim: the tool layer MATCHES it against a
   * closed table and publishes the table's constant, never this string.
   */
  ownAnswer: string | null;
  /** Which side of 18-01's measurement this resource sits on. */
  evidence: SchedulingEvidence;
  /**
   * Everybody else on the invitation, in document order (D-10).
   *
   * Read off ONE component — the master when there is one, else the first —
   * because a master and its overrides each repeat the list, and reading every
   * component would list each person once per edited date.
   *
   * **Two kinds of line are left out, and both on purpose.** The user's own
   * line or lines, matched by `isOwnAddress` against the account's own address
   * set: the user is not "another attendee", and their address must not reach
   * a response (RSVP-02). And the organiser's own attendee line, when the
   * organiser also sits on the list (both measured copies carry one): the
   * preview names the organiser separately and says whether they are told, so
   * counting them again among the people who are "not told directly" would
   * make the preview contradict itself.
   */
  others: InvitationAttendee[];
  /**
   * The resource's UID, off the same component as `others`, or null. Read so a
   * conflict sweep can recognise a copy of THIS invitation on another calendar
   * as the invitation rather than as a clash with it. Untrusted, and never
   * published: it is compared, not shown.
   */
  uid: string | null;
  /**
   * The dates of a series the user answered on their own (OQ6), in document
   * order: every override component carrying the user's line whose `PARTSTAT`
   * differs from the one on the master's line.
   *
   * A whole-series answer rewrites every one of these, so the preview names
   * them before a token is used. Compared with RFC 5545's default applied —
   * a line with no `PARTSTAT` has not answered, which is `NEEDS-ACTION` — and
   * case-folded, because the values are case-insensitive. Empty on a one-off
   * resource and on one with no master: there is no series answer to differ
   * from. Every field is read verbatim and untrusted.
   */
  separateAnswers: SeparateAnswer[];
}

/** One date of a series the user answered separately. Every field untrusted. */
export interface SeparateAnswer {
  /** The override's `RECURRENCE-ID`, as its own wall clock. */
  recurrenceLocal: string;
  /** The same instant in seconds since the epoch; absent when it has none. */
  recurrenceUtc?: number;
  /** The zone `recurrenceLocal` is in, as `readEventTime` reports it. */
  recurrenceTzid: string;
  /** The raw `PARTSTAT` on the user's line of that override, or null. */
  partstat: string | null;
}

/**
 * The scheduling-agent values RFC 6638 § 7.1 defines as "the server does not
 * schedule for this person". Upper-case, compared after folding.
 */
const CLIENT_SCHEDULED = new Set(["CLIENT", "NONE"]);

/**
 * Read the facts a reply preview states, from the stored bytes and the one
 * server-side marker that decides who is told.
 *
 * ## Which marker decides, and why it is this one
 *
 * 18-01 read both sides on the live account on 2026-09-26. The copy iCloud
 * itself delivered carried a `Schedule-Tag`, and answering it told the
 * organiser. The copy imported from a `.ics` carried none — the property came
 * back 404 — and answering it told nobody. `SCHEDULE-STATUS` was absent on
 * BOTH, before and after, so it is not read here at all: D-09's first wording
 * would have called a real invitation "nobody is told".
 *
 * `scheduleTag` is that marker, read by the caller out of the same multi-status
 * the body came from. It is a server statement under RFC 6638, not a value the
 * organiser wrote, which is why it is the one that decides.
 *
 * ## Why absence alone does not say "nobody"
 *
 * One sample of each was measured. A tag present is the server saying it
 * schedules this resource, and that side is safe to state. A tag ABSENT is
 * weaker: it is what an imported copy looked like, and it is also what any
 * scheduling object would look like if the property were ever not returned.
 * "Nobody is told" is the one sentence that is harmful when wrong, because a
 * reply cannot be unsent. So absence becomes `imported-copy` only when the
 * bytes CORROBORATE it with the other marker 18-01 saw on the imported side: a
 * `SCHEDULE-AGENT` of `CLIENT` or `NONE` on the organiser or on the user's own
 * line, which RFC 6638 defines as "the server does not schedule for this
 * person". Without it the answer is `undetermined`.
 *
 * Untrusted values are returned verbatim, on this module's rule.
 */
export function invitationFactsOf(
  icsText: string,
  addresses: readonly string[],
  scheduleTag: string | null,
): InvitationFacts {
  return withParsedResource(icsText, (resource) => {
    let organizerLine: IcalProperty | null = null;
    let ownAnswer: string | null = null;
    let answered = false;
    let clientScheduled = false;

    // The master first, then the rest in document order (18-REVIEW WR-06).
    // RFC 5545 does not put the master first, and an edited date that came
    // first would otherwise lend the series its own separate answer, while
    // `separateAnswersOf` compares against the master's. The fallback without
    // a master is the first component that carries the user's line.
    const master = resource.components.find((one) => !one.hasProperty("recurrence-id"));
    const ordered =
      master === undefined
        ? resource.components
        : [master, ...resource.components.filter((one) => one !== master)];

    for (const component of ordered) {
      for (const organizer of component.getAllProperties("organizer")) {
        if (organizerLine === null) organizerLine = organizer;
        if (isClientScheduled(organizer)) clientScheduled = true;
      }
      for (const attendee of component.getAllProperties("attendee")) {
        if (!namesUser(attendee, addresses)) continue;
        if (!answered) {
          ownAnswer = firstParameter(attendee, "partstat");
          answered = true;
        }
        if (isClientScheduled(attendee)) clientScheduled = true;
      }
    }

    const evidence: SchedulingEvidence =
      scheduleTag !== null
        ? "scheduling-object"
        : clientScheduled
          ? "imported-copy"
          : "undetermined";

    const organizer: InvitationOrganizer =
      organizerLine === null
        ? { name: null, address: null }
        : { name: nonEmpty(firstParameter(organizerLine, "cn")), address: addressOf(organizerLine) };

    // The master when there is one: it carries the list every override repeats.
    const listed =
      resource.components.find((one) => !one.hasProperty("recurrence-id")) ??
      resource.components[0] ??
      null;
    const others: InvitationAttendee[] = [];
    for (const attendee of listed?.getAllProperties("attendee") ?? []) {
      if (namesUser(attendee, addresses)) continue;
      if (organizerLine !== null && sameParty(attendee, organizerLine)) continue;
      others.push({
        name: firstParameter(attendee, "cn"),
        email: addressOf(attendee),
        partstat: firstParameter(attendee, "partstat"),
      });
    }

    const uid = textOf(listed?.getFirstPropertyValue("uid"));

    return {
      organizer,
      ownAnswer,
      evidence,
      others,
      uid,
      separateAnswers: separateAnswersOf(resource, addresses),
    };
  });
}

/**
 * The override answers that differ from the master's (OQ6). See
 * `InvitationFacts.separateAnswers`.
 */
function separateAnswersOf(
  resource: ParsedCalendarResource,
  addresses: readonly string[],
): SeparateAnswer[] {
  const master = resource.components.find((one) => !one.hasProperty("recurrence-id"));
  if (master === undefined) return [];

  const ownPartstat = (component: IcalComponent): { found: boolean; raw: string | null } => {
    const line = component
      .getAllProperties("attendee")
      .find((attendee) => namesUser(attendee, addresses));
    return line === undefined
      ? { found: false, raw: null }
      : { found: true, raw: firstParameter(line, "partstat") };
  };
  const folded = (raw: string | null): string => (raw ?? "NEEDS-ACTION").toUpperCase();

  const masterAnswer = folded(ownPartstat(master).raw);
  const separate: SeparateAnswer[] = [];
  for (const component of resource.components) {
    if (component === master) continue;
    const value = component.getFirstPropertyValue("recurrence-id");
    if (!(value instanceof ICAL.Time)) continue;
    const own = ownPartstat(component);
    if (!own.found || folded(own.raw) === masterAnswer) continue;

    const time = readEventTime(value, requestedTzidOf(component, "recurrence-id"));
    const row: SeparateAnswer = {
      recurrenceLocal: time.local,
      recurrenceTzid: time.tzid,
      partstat: own.raw,
    };
    // Assigned rather than spread, so an absent instant stays ABSENT.
    if (time.utc !== undefined) row.recurrenceUtc = time.utc;
    separate.push(row);
  }
  return separate;
}

/** A string, or null when it is absent or empty. */
function nonEmpty(value: string | null): string | null {
  return value !== null && value.length > 0 ? value : null;
}

/**
 * The address one `ORGANIZER` or `ATTENDEE` line would be reached at: the
 * `mailto:` value, else the `EMAIL` parameter, else null. Verbatim.
 */
function addressOf(property: IcalProperty): string | null {
  const value = calAddressOf(property);
  if (value !== null && value.toLowerCase().startsWith(MAILTO_PREFIX)) {
    const address = value.slice(MAILTO_PREFIX.length);
    if (address.length > 0) return address;
  }
  return nonEmpty(firstParameter(property, "email"));
}

/**
 * Whether an attendee line names the same person as the organiser line.
 *
 * The same value exactly (an opaque principal path compares only that way, on
 * `isOwnAddress`'s rule), or the same address once folded. Used only to keep
 * the organiser out of the other-attendees list, never to decide who is told.
 */
function sameParty(attendee: IcalProperty, organizer: IcalProperty): boolean {
  const value = calAddressOf(attendee);
  if (value !== null && value.length > 0 && value === calAddressOf(organizer)) {
    return true;
  }
  const one = addressOf(attendee);
  const two = addressOf(organizer);
  return one !== null && two !== null && one.toLowerCase() === two.toLowerCase();
}

/** Whether a line says the server does not schedule for this person. */
function isClientScheduled(property: IcalProperty): boolean {
  const agent = firstParameter(property, "schedule-agent");
  return agent !== null && CLIENT_SCHEDULED.has(agent.toUpperCase());
}

// ---------------------------------------------------------------------------
// Narrowing a series — the two operations a SCOPED DELETE is built from
//
// **Neither of these is a delete, and that is the whole subject.** A recurring
// resource holds the WHOLE series in one object, so removing one date from it
// is a conditional WRITE that narrows the rule, and removing everything from a
// date onward is a conditional write that bounds it. Only the whole-series case
// is an actual `DELETE`, and that one shipped in plan 05-07.
//
// Both operations are PURE and socket-free, both return CLONES of every
// component they did not change, and both return the same three-armed answer.
// One shared result type rather than two identically-shaped ones, because the
// caller dispatches on the arms rather than on which operation produced them —
// and two types would let the two operations drift into different arm sets with
// nothing going red.
// ---------------------------------------------------------------------------

/**
 * What a narrowing operation leaves behind.
 *
 * `no-occurrences` is the arm that matters, and it exists so that a caller
 * DELETES the resource instead of writing it. A series that produces nothing is
 * a resource that shows up in no listing, cannot be found by any search, and
 * therefore cannot be cleaned up through this tool surface ever again — a ghost
 * this project would have created and could not remove.
 *
 * `not-a-series` is the resource-shaped refusal: there is no rule here to
 * narrow. It is deliberately DISTINCT from `no-occurrences`, because collapsing
 * the two would answer "delete the whole thing" to a resource this operation
 * simply does not apply to.
 */
export type SeriesNarrowing =
  | {
      kind: "narrowed";
      /** The component list to serialise. Every entry is a clone. */
      components: IcalComponent[];
    }
  | { kind: "no-occurrences" }
  | { kind: "not-a-series" };

/** The two arms that carry no payload, allocated once. */
const NO_OCCURRENCES: SeriesNarrowing = Object.freeze({
  kind: "no-occurrences",
} as const);
const NOT_A_SERIES: SeriesNarrowing = Object.freeze({
  kind: "not-a-series",
} as const);

/**
 * Advance the revision and the timestamp on a master a narrowing just rewrote.
 *
 * **A narrowing is a CHANGE to the event, so it earns a new revision like every
 * other change this server writes (05-REVIEW.md WR-03).** Neither narrowing did,
 * while `applyOccurrenceOverride` and `applyEventChange` both do — three writers
 * advancing it and two not, with the asymmetry recorded nowhere. (It was
 * `updateEventBody` beside the first of those until D-02 replaced the rewrite with
 * a patch; the count and the argument are unchanged, only the name.)
 *
 * `nextSequence`'s own docstring is why that is not cosmetic: a revision that
 * does not advance raises nothing anywhere — not here, not at iCloud, not in the
 * attendee's client. The change is simply treated as stale and ignored, and *no
 * layer reports a problem*.
 *
 * **It matters on an INVITED series, and that is exactly the case this path is
 * open for.** A scoped delete of a series carrying `ATTENDEE` is reachable and
 * clones every one of those lines byte for byte. Without a new revision the
 * preview will have said
 * *N people will be told*, the outcome will report `recipientCount: N`, and a
 * recipient's client comparing this number against the copy it holds has grounds
 * to discard the update — so the meeting stays on their calendar with nothing
 * reporting a problem at any layer.
 *
 * Advanced UNCONDITIONALLY rather than only when the resource carries people, on
 * the precedent of the other three writers. Making the revision depend on the
 * resource's shape would mean two rules for one property, and RFC 5545 §3.8.7.4
 * asks for the bump on any significant change — an `EXDATE` or a bounded rule is
 * one — whether or not anybody is watching.
 *
 * `DTSTAMP` moves with it, on `applyOverrideChange`'s pattern: it is when this
 * version of the object was created, and a narrowing creates one.
 */
function reviseNarrowedMaster(master: IcalComponent): void {
  master.updatePropertyWithValue(
    "dtstamp",
    utcTimeAt(Math.floor(Date.now() / 1000)),
  );
  master.updatePropertyWithValue(
    "sequence",
    nextSequence(sequenceOfComponent(master)),
  );
}

/**
 * Remove ONE date from a series, and leave every other date exactly where it is.
 *
 * ## It is a MEASUREMENT rather than a reading of the RFC
 *
 * Probe P-8 half A in `05-UAT.md` added one exclusion to a master on the live
 * account on 2026-08-22 and read the series back. Verbatim, from its recorded
 * answer:
 *
 * > **`EXDATE` removes exactly one.**
 * >
 * > | Occurrence | Present |
 * > |---|---|
 * > | 2026-09-01 15:00 | yes |
 * > | 2026-09-08 15:00 | yes |
 * > | 2026-09-15 | **gone** |
 * > | 2026-09-22 15:00 | yes |
 * >
 * > Exactly one date removed, every other occurrence intact at its original
 * > time.
 *
 * So the shape is settled, and what is left is writing an exclusion the server
 * will actually match.
 *
 * ## The value type and the zone are read off the PROPERTY
 *
 * The excluded value is built from the master's own `DTSTART` property — its
 * value TYPE and its zone — rather than from a parsed occurrence, which has
 * already been normalised. A date-valued series takes a date-valued exclusion;
 * a zoned series takes a datetime exclusion carrying the same zone parameter.
 *
 * **A mismatch here does not error.** It produces a resource whose exclusion
 * silently matches nothing, so the occurrence stays and the user believes it is
 * gone. That is the worst shape a bug can have on this path, and it is the same
 * shape the `ical-jsdate` scan rule exists to prevent one layer down — which is
 * why nothing here converts through a host date at any point.
 *
 * The recurrence identifier arrives in WIRE form, which is what the opaque
 * event id carries. It is read into the master's own value by CONSTRUCTION: the
 * calendar fields are lifted out of the string and handed to a new time wearing
 * the master's zone and the master's date-versus-date-time nature. Nothing
 * decides what zone a bare wall clock is in, because nothing has to.
 *
 * ## The override goes with the date
 *
 * A component carrying the target recurrence identifier is REMOVED in the same
 * operation. An override for a date the series no longer produces is an orphan,
 * and leaving one behind is how a resource ends up showing a "deleted" meeting
 * in some clients and not in others. Plan 05-12 handles orphans that arrive
 * from elsewhere; this operation must not create one.
 *
 * ## Excluding twice is excluding once
 *
 * The comparison against the existing exclusions is made in the same value type
 * and zone the SERVER will compare in, so a duplicate cannot arrive wearing a
 * different spelling. An already-excluded date is therefore a no-op rather than
 * a second entry.
 *
 * ## The master comes back at a NEW revision
 *
 * `SEQUENCE` is advanced and `DTSTAMP` refreshed on the narrowed master, on the
 * same footing as every other writer in this tree. See `reviseNarrowedMaster`
 * for why a stalled revision on an invited series is a silent failure rather
 * than an untidy one.
 */
export function applyExdate(
  resource: ParsedCalendarResource,
  recurrenceId: string,
): SeriesNarrowing {
  const master = resource.master;
  if (master === null) return NOT_A_SERIES;

  const excluded = timeLikeStart(master, recurrenceId);
  if (excluded === null) return NOT_A_SERIES;

  const components = resource.components.map(cloneComponent);
  const narrowedMaster = components[resource.components.indexOf(master)]!;

  // The override for this date goes with it. Matched on the identifier rather
  // than on the rule, because an override whose slot the rule no longer
  // produces is still a component of this resource.
  const kept = components.filter(
    (component) =>
      component === narrowedMaster ||
      recurrenceIdStringOf(component) !== recurrenceId,
  );

  const wire = excluded.toICALString();
  if (!excludedWiresOf(narrowedMaster).includes(wire)) {
    narrowedMaster.addProperty(anchoredExclusion(master, excluded));
  }

  // A new revision, because the series really did change — see
  // `reviseNarrowedMaster`, which carries the argument. Run even on the
  // already-excluded no-op path: this operation is only ever called because
  // somebody asked for the date to be gone, and a second request is still a
  // write going out.
  reviseNarrowedMaster(narrowedMaster);

  return producesNothing(narrowedMaster, kept)
    ? NO_OCCURRENCES
    : { kind: "narrowed", components: kept };
}

/**
 * Stop a series from one date onward, and keep every date before it.
 *
 * ## What survives, and why that is the load-bearing half
 *
 * Everything strictly before the chosen occurrence, untouched — including its
 * overrides. Those describe meetings that ALREADY HAPPENED, and erasing them
 * rewrites history the user did not ask to rewrite. Every occurrence at or
 * after the chosen one goes, override included.
 *
 * ## The bound, and the three cases RFC 5545 §3.3.10 actually defines
 *
 * The rule is set to terminate at the last instant before the chosen
 * occurrence's start. §3.3.10 was re-read directly from RFC 5545 for this,
 * rather than taken from a summary, and it says three things rather than two —
 * verbatim:
 *
 * > The value of the UNTIL rule part MUST have the same value type as the
 * > "DTSTART" property.  Furthermore, if the "DTSTART" property is specified as
 * > a date with local time, then the UNTIL rule part MUST also be specified as a
 * > date with local time.  If the "DTSTART" property is specified as a date with
 * > UTC time or a date with local time and time zone reference, then the UNTIL
 * > rule part MUST be specified as a date with UTC time.
 *
 * So: a date start takes a date bound; a FLOATING start takes a floating bound;
 * a UTC or zoned start takes a UTC bound. The floating case is the one a
 * "zoned means UTC" reading gets wrong, and a bound of the wrong kind is a
 * resource other clients read wrongly — which on this path means occurrences
 * the user believes are cancelled continuing to appear on somebody else's
 * calendar.
 *
 * The same section also settles the arithmetic: the bound is INCLUSIVE ("bounds
 * the recurrence rule in an inclusive manner"), so it must name the instant
 * BEFORE the chosen start rather than the start itself.
 *
 * The instant is taken through the library's ABSOLUTE accessor — the
 * seconds-since-epoch one — and never through the host-runtime date conversion
 * this tree's scan bans by name. That ban's own stated reasoning is exactly
 * this case: the value the conversion produces depends on the host machine's
 * zone, the test pool inherits the developer's zone while production runs UTC,
 * and the failure is not an error but silently wrong times. See the Conventions
 * section of `./.claude/CLAUDE.md`, which is where the token itself may be
 * spelled; naming it here would fail the very check this paragraph explains.
 *
 * ## A count cannot survive a bound
 *
 * A rule carrying a repetition COUNT has it REPLACED by the bound rather than
 * kept beside it. The two are different claims — "four of them, wherever they
 * fall" against "everything up to this instant" — and RFC 5545's own grammar
 * admits at most one of them. A reader seeing the count disappear should read
 * it as the only legal way to express the request rather than as data loss.
 *
 * ## The dates a rule does not produce
 *
 * A resource may also name individual dates outright. Those at or after the
 * bound are removed too: a bound the rule respects and a date list that ignores
 * it would leave occurrences standing that the preview said were gone.
 *
 * ## Truncating from the first occurrence
 *
 * There is nothing before it to keep, so the answer is `no-occurrences` and the
 * caller removes the resource. That falls out of the emptiness check rather
 * than being a special case: a bound before the start is a rule that produces
 * nothing, which is the ghost `applyExdate` already refuses to create.
 *
 * ## The master comes back at a NEW revision
 *
 * As `applyExdate` does, and for the same reason — see `reviseNarrowedMaster`.
 * This is the sharper of the two: it removes every occurrence from the chosen
 * date onward, so a recipient's client discarding it as stale keeps a whole tail
 * of a series the user believes they have cancelled.
 */
export function truncateSeries(
  resource: ParsedCalendarResource,
  recurrenceId: string,
): SeriesNarrowing {
  const master = resource.master;
  if (master === null) return NOT_A_SERIES;

  const chosen = timeLikeStart(master, recurrenceId);
  if (chosen === null) return NOT_A_SERIES;

  const components = resource.components.map(cloneComponent);
  const narrowedMaster = components[resource.components.indexOf(master)]!;

  // Compared on the ABSOLUTE instant rather than on the wire string, so a
  // resource whose overrides were written in a different spelling from the
  // master's still sorts correctly against the bound.
  const from = chosen.toUnixTime();
  const kept = components.filter((component) => {
    if (component === narrowedMaster) return true;
    const value = component.getFirstPropertyValue("recurrence-id");
    if (!(value instanceof ICAL.Time)) return true;
    return value.toUnixTime() < from;
  });

  boundRule(narrowedMaster, lastInstantBefore(chosen));
  dropDatesFrom(narrowedMaster, from);
  // Same revision bump as `applyExdate`, and the sharper case of the two: this
  // one removes every occurrence from a date onward. See `reviseNarrowedMaster`.
  reviseNarrowedMaster(narrowedMaster);

  return producesNothing(narrowedMaster, kept)
    ? NO_OCCURRENCES
    : { kind: "narrowed", components: kept };
}

/**
 * How many removed dates a narrowing will NAME before it stops naming them.
 *
 * A presentation cap rather than a correctness one, and the difference matters:
 * the authoritative number of removed occurrences is the count the preview
 * publishes in its TRUSTED half, which is a walk of the rule. This bounds the
 * LIST of dates that rides beside it, because a truncation of an endless rule
 * removes more dates than any response should carry and a caller reading fifty
 * of them has understood the shape of what is about to happen.
 */
export const MAX_NAMED_REMOVALS = 50;

/**
 * The occurrence starts a narrowing removed, read off the narrowing's OWN
 * output.
 *
 * **Differenced rather than predicted, and that is the whole point of taking
 * both components.** A separate "which dates would this remove" rule would be a
 * second implementation of the operation, and two implementations of one
 * question is precisely how a preview stops being a safeguard. This walks the
 * master as it WAS and the master as the narrowing LEFT it, and reports what
 * the first produces and the second does not.
 *
 * Both walks share one horizon, which is what keeps an endless rule honest:
 * without it the second walk would run out of slots first and every date past
 * its end would read as removed. Slots beyond the shared horizon are examined
 * by neither.
 *
 * The wall clocks are assembled from each slot's own calendar fields, so the
 * answer carries no dependency on the host machine's zone.
 */
export function removedStartsOf(
  before: IcalComponent,
  after: IcalComponent,
  cap: number = MAX_NAMED_REMOVALS,
  horizon: number = MAX_EXPANDED_OCCURRENCES,
): string[] {
  const survivors = new Set<string>();
  const surviving = new ICAL.Event(after).iterator();
  let seen = 0;
  let slot: IcalTime | null | undefined = surviving.next();
  while (slot && seen < horizon) {
    survivors.add(slot.toICALString());
    seen += 1;
    slot = surviving.next();
  }

  const removed: string[] = [];
  const original = new ICAL.Event(before).iterator();
  seen = 0;
  slot = original.next();
  while (slot && seen < horizon && removed.length < cap) {
    if (!survivors.has(slot.toICALString())) removed.push(wallClock(slot));
    seen += 1;
    slot = original.next();
  }

  return removed;
}

/** The dates a forward-reaching override does NOT move, counted and named. */
export interface PinnedOccurrences {
  /**
   * How many of them there are, up to the expansion horizon.
   *
   * **Uncapped where the list is capped**, and the asymmetry is the same one
   * `MAX_NAMED_REMOVALS` draws: the number is subtracted from a published count
   * and must therefore be exact, while the list is presentation and stops at
   * fifty.
   */
  count: number;
  /** Their master-series slots, as local wall clocks. Capped. */
  starts: string[];
}

/**
 * The slots after one date that keep their OWN edit when a range override lands.
 *
 * **This exists because "everything from here onward moves" is very nearly true
 * and the gap is invisible.** A direct exception outranks a ranged one — the
 * library's own expander checks the exact recurrence identifier first and only
 * then looks for a range — so a date somebody already moved by hand stays where
 * they put it. That is the correct reading and the kind one: an individually
 * edited date is usually an arrangement made with somebody else, and absorbing
 * it into a bulk change would destroy a decision nobody asked to revisit.
 *
 * What it must not do is go unmentioned. A preview promising twelve while eleven
 * move is the failure this whole phase is built against, so the count here is
 * SUBTRACTED from the published number rather than merely noted, and the dates
 * ride beside it so the answer is an answer rather than an arithmetic surprise.
 *
 * The named slot itself is excluded — it is the one being edited, so it is the
 * change rather than an exception to it. A masterless resource has no rule for
 * a range to reach along and reports nothing.
 */
export function pinnedOccurrencesAfter(
  resource: ParsedCalendarResource,
  recurrenceId: string,
  cap: number = MAX_NAMED_REMOVALS,
  horizon: number = MAX_EXPANDED_OCCURRENCES,
): PinnedOccurrences {
  const master = resource.master;
  if (master === null) return { count: 0, starts: [] };

  const overridden = new Set<string>();
  for (const component of resource.components) {
    const id = recurrenceIdStringOf(component);
    if (id !== null) overridden.add(id);
  }

  const starts: string[] = [];
  let count = 0;
  let passed = false;
  let seen = 0;

  const iterator = new ICAL.Event(master).iterator();
  let slot: IcalTime | null | undefined = iterator.next();
  while (slot && seen < horizon) {
    const key = slot.toICALString();
    // Read BEFORE `passed` is set, so the named slot is never counted as one of
    // the dates its own edit fails to reach.
    if (passed && overridden.has(key)) {
      count += 1;
      if (starts.length < cap) starts.push(wallClock(slot));
    }
    if (key === recurrenceId) passed = true;
    seen += 1;
    slot = iterator.next();
  }

  return { count, starts };
}

/**
 * Take ONE edited date out of a resource that has no rule behind its dates.
 *
 * ## The shape this exists for, and why it is real rather than defensive
 *
 * A resource whose every component carries a recurrence identifier and which
 * holds no master is what remains when the series that produced the overrides
 * was deleted somewhere else. The READ side has answered correctly for it since
 * 03-03 — the expansion path is chosen by the master being ABSENT rather than by
 * a flag, so such a resource returns its components instead of nothing — and
 * this is the write side's matching answer.
 *
 * ## Why it is a separate operation rather than an arm of `applyExdate`
 *
 * `applyExdate` narrows a RULE, and the exclusion it writes is a claim about
 * what the rule produces. There is no rule here, so an exclusion would be a
 * property with nothing to exclude from — legal bytes that change nothing, which
 * is the silent shape this module works hardest to avoid. Dropping the component
 * is the whole operation, and it is a different operation.
 *
 * ## The three arms mean what they mean everywhere else
 *
 * `not-a-series` is the shape refusal: a resource that HAS a master is narrowed
 * by the rule operations rather than by this one, and a date this resource does
 * not carry names nothing to drop. `no-occurrences` is the last component going,
 * which the caller answers by removing the resource — the same ghost-avoidance
 * `producesNothing` argues for one shape over.
 */
export function dropOverride(
  resource: ParsedCalendarResource,
  recurrenceId: string,
): SeriesNarrowing {
  if (resource.master !== null) return NOT_A_SERIES;

  const target = resource.components.some(
    (component) => recurrenceIdStringOf(component) === recurrenceId,
  );
  if (!target) return NOT_A_SERIES;

  const kept = resource.components
    .filter((component) => recurrenceIdStringOf(component) !== recurrenceId)
    .map(cloneComponent);

  return kept.length === 0 ? NO_OCCURRENCES : { kind: "narrowed", components: kept };
}

/**
 * The last instant before one occurrence's start, in the form §3.3.10 requires.
 *
 * Three arms, matching the three the section defines. The date arm steps back a
 * whole day rather than a second, because a date has no seconds to step through
 * and the bound has to remain a date.
 */
function lastInstantBefore(start: IcalTime): IcalTime {
  if (start.isDate) return start.clone().adjust(-1, 0, 0, 0);
  // A floating start is a date with LOCAL time, and its bound must be one too.
  // Stepping the wall clock back keeps it floating; converting to an instant
  // would invent an anchor the resource never claimed.
  if (start.zone.tzid === FLOATING_TZID) {
    return start.clone().adjust(0, 0, 0, -1);
  }
  // UTC or a named zone: the bound MUST be UTC.
  return utcTimeAt(start.toUnixTime() - 1);
}

/**
 * Set the master's rule to terminate at one instant, replacing what was there.
 *
 * A component with no rule is left alone rather than given one: this operation
 * narrows what a resource already claims, and a resource naming its dates
 * outright is narrowed by the date list below instead.
 */
function boundRule(component: IcalComponent, bound: IcalTime): void {
  const property = component.getFirstProperty("rrule");
  if (property === null) return;

  const recur = property.getFirstValue();
  if (!(recur instanceof ICAL.Recur)) return;

  const bounded = recur.clone();
  // Cleared FIRST, because a rule may carry only one of the two and the
  // serialiser emits whichever it finds.
  bounded.count = null;
  bounded.until = bound;
  property.setValue(bounded);
}

/**
 * Remove every individually-named date at or after an instant.
 *
 * A multi-value line is rebuilt from the values that survive rather than
 * dropped whole, so a resource naming four dates on one line keeps the two that
 * are before the bound.
 */
function dropDatesFrom(component: IcalComponent, from: number): void {
  const surviving: IcalTime[] = [];
  let found = false;

  for (const property of component.getAllProperties("rdate")) {
    found = true;
    for (const value of property.getValues()) {
      if (value instanceof ICAL.Time && value.toUnixTime() < from) {
        surviving.push(value);
      }
    }
  }
  if (!found) return;

  component.removeAllProperties("rdate");
  for (const value of surviving) {
    const property = new ICAL.Property("rdate");
    property.setValue(value);
    component.addProperty(property);
  }
}

/**
 * A time wearing the master's start value's TYPE and ZONE, at a wire instant.
 *
 * **Constructed rather than parsed**, and that is the load-bearing choice. The
 * library's string parsers want the format's extended form, and handing one a
 * bare wall clock would mean deciding what zone it is in — the floating-time
 * ambiguity this module exists to keep out of comparisons. Lifting the calendar
 * fields out of the wire string and handing them to a new time built on the
 * master's own zone decides nothing: the zone and the date-versus-date-time
 * nature both come from the property, and the fields are digits.
 *
 * A wire string whose shape disagrees with the master's is refused rather than
 * coerced. A date-time identifier against an all-day series names nothing the
 * series produces, and silently rounding one into the other is how an exclusion
 * ends up matching a date nobody asked to remove.
 */
function timeLikeStart(
  master: IcalComponent,
  recurrenceId: string,
): IcalTime | null {
  const property = master.getFirstProperty("dtstart");
  if (property === null) return null;

  const template = property.getFirstValue();
  if (!(template instanceof ICAL.Time)) return null;

  const parts = WIRE_TIME.exec(recurrenceId);
  if (parts === null) return null;

  const isDate = template.isDate;
  // `parts[4]` is present exactly when the wire string carries a time.
  if (isDate !== (parts[4] === undefined)) return null;
  // And the UTC suffix must agree with the property's own anchoring. A slot
  // this server produced always does — the identifier is the master's own
  // `toICALString()` — but a `Z` against a zoned master would otherwise be read
  // as a wall clock in that zone, which is the same instant only by accident.
  if (
    !isDate &&
    (parts[7] === "Z") !== (template.zone === ICAL.Timezone.utcTimezone)
  ) {
    return null;
  }

  return new ICAL.Time(
    {
      year: Number(parts[1]),
      month: Number(parts[2]),
      day: Number(parts[3]),
      hour: isDate ? 0 : Number(parts[4]),
      minute: isDate ? 0 : Number(parts[5]),
      second: isDate ? 0 : Number(parts[6]),
      isDate,
    },
    template.zone,
  );
}

/**
 * A date, or a date and a time, in the format's own BASIC form.
 *
 * Basic rather than extended, because that is what a recurrence identifier
 * carries on the wire and what `ICAL.Time#toICALString` emits — the two ends of
 * this comparison have to spell the same instant the same way.
 */
const WIRE_TIME = /^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?$/;

/**
 * The `EXDATE` property naming one excluded value, in the master's own form.
 *
 * `recurrenceIdProperty`'s shape exactly, and for the same reason: the zone
 * travels as a PARAMETER copied verbatim from the master's `DTSTART`, and
 * `VALUE=DATE` is emitted by the serialiser from the value's own type. No
 * parameter is written for a date, because a date is anchored to nothing by
 * definition and a `TZID` beside one is a claim the master never made.
 */
function anchoredExclusion(
  master: IcalComponent,
  value: IcalTime,
): IcalProperty {
  const property = new ICAL.Property("exdate");
  const tzid = requestedTzidOf(master, "dtstart");
  if (tzid !== null && !value.isDate) property.setParameter("tzid", tzid);
  property.setValue(value);
  return property;
}

/**
 * Every value one component's exclusions carry, in wire form.
 *
 * `EXDATE` is a comma-separated multi-value property, so a component carrying
 * one line may be excluding several dates. Reading only the first value of each
 * property would let a duplicate through on a resource some other client wrote.
 */
function excludedWiresOf(component: IcalComponent): string[] {
  const wires: string[] = [];
  for (const property of component.getAllProperties("exdate")) {
    for (const value of property.getValues()) {
      if (value instanceof ICAL.Time) wires.push(value.toICALString());
    }
  }
  return wires;
}

/**
 * Whether a narrowed resource would produce nothing at all.
 *
 * Two conditions, and the second is the conservative half: the narrowed master
 * yields no occurrence, AND no component other than the master survives. A
 * resource still carrying an override is one some client will still render, so
 * reporting it empty would delete an event the user can see. Erring toward
 * WRITING rather than deleting is the only safe direction here.
 */
function producesNothing(
  master: IcalComponent,
  components: IcalComponent[],
): boolean {
  if (components.some((component) => component !== master)) return false;
  const first = new ICAL.Event(master).iterator().next();
  return first === null || first === undefined;
}

/**
 * A component that shares no state with the one it was made from.
 *
 * `Component#toJSON()` returns the LIVE jCal array — the library's own
 * documentation says so and says to clone it before modifying — so wrapping it
 * directly would produce a second `Component` writing through to the first. The
 * JSON round trip is the deep copy; jCal is plain arrays, strings and numbers,
 * so nothing is lost in it and nothing needs a structured clone.
 *
 * The result has NO parent, which matters: a property added to it must not be
 * able to resolve a `TZID` by walking up into the original resource's tree.
 */
function cloneComponent(component: IcalComponent): IcalComponent {
  return new ICAL.Component(JSON.parse(JSON.stringify(component.toJSON())));
}

/** The recurrence identifier one component carries, in wire form, or null. */
function recurrenceIdStringOf(component: IcalComponent): string | null {
  const value = component.getFirstPropertyValue("recurrence-id");
  return value instanceof ICAL.Time ? value.toICALString() : null;
}

/**
 * The master's own slot for one recurrence identifier, as a time.
 *
 * **Taken from the iterator rather than parsed out of the wire string**, and
 * that is the load-bearing choice in this file. A slot the iterator yields
 * descends from the master's own `DTSTART`, so it carries the master's zone and
 * the master's date-versus-date-time nature by construction — which is exactly
 * what the recurrence identifier has to be expressed in. Parsing the string
 * instead would mean deciding what zone a bare wall clock is in, which is the
 * floating-time ambiguity this module exists to keep out of comparisons, and it
 * would mean hand-converting the format's basic form into the extended one the
 * library's string parsers expect.
 *
 * The walk stops once it has passed the slot asked for, on `findOccurrence`'s
 * own measured reason: without it an identifier the rule no longer produces
 * costs the full step cap to answer "no", on an unbounded weekly rule that a
 * real calendar is mostly made of.
 *
 * A slot the rule EXCLUDES is never yielded, so an attempt to edit an excluded
 * date returns null and is refused. That is the right answer: the series does
 * not produce that date, so there is no occurrence there to move.
 */
function slotOf(
  master: IcalComponent,
  recurrenceId: string,
  maxSteps: number = MAX_ITERATOR_STEPS,
): IcalTime | null {
  const iterator = new ICAL.Event(master).iterator();
  let steps = 0;

  let next: IcalTime | null | undefined = iterator.next();
  while (next) {
    steps += 1;
    if (steps > maxSteps) return null;

    const key = next.toICALString();
    // Cloned, because the iterator is free to hand back the same object again.
    if (key === recurrenceId) return next.clone();
    if (key > recurrenceId) return null;

    next = iterator.next();
  }

  return null;
}

/**
 * The `RECURRENCE-ID` property naming one slot, in the master's own form.
 *
 * The zone travels as a PARAMETER copied verbatim from the master's `DTSTART`,
 * and the value is the slot time itself. `VALUE=DATE` is emitted by the
 * serialiser from the value's own type, which is `anchoredTime`'s argument one
 * section up: an all-day series yields date slots, so an all-day series gets a
 * date-valued identifier without this function deciding anything.
 *
 * No parameter is written for a date, because a date is anchored to nothing by
 * definition and a `TZID` beside one is a claim the master never made.
 */
function recurrenceIdProperty(
  master: IcalComponent,
  slot: IcalTime,
  range: OverrideRange = "this-only",
): IcalProperty {
  const property = new ICAL.Property("recurrence-id");
  const tzid = requestedTzidOf(master, "dtstart");
  if (tzid !== null && !slot.isDate) property.setParameter("tzid", tzid);
  property.setValue(slot);
  applyRangeTo(property, range);
  return property;
}

/**
 * Assert one override's REACH on the component that carries it.
 *
 * Written in both directions rather than only the forward one. A component that
 * already reached forward and is being edited for one date alone must stop
 * reaching, and leaving the parameter in place would silently move every later
 * date on an edit whose preview promised one — which is the exact failure the
 * whole scope vocabulary exists to prevent, arrived at by omission.
 *
 * A component with no recurrence identifier is left alone: it is the master, and
 * a reach parameter on a master is a claim about a slot it does not occupy.
 */
function applyRange(component: IcalComponent, range: OverrideRange): void {
  const property = component.getFirstProperty("recurrence-id");
  if (property === null) return;
  applyRangeTo(property, range);
}

/**
 * The parameter itself, in the one spelling RFC 5545 §3.2.13 defines.
 *
 * The value is a literal here rather than a constant elsewhere because it is
 * read back by exactly one thing — the library's own expander, which compares
 * against its own `THISANDFUTURE` — and a second name for it would be a second
 * place for the two spellings to drift apart.
 */
function applyRangeTo(property: IcalProperty, range: OverrideRange): void {
  if (range === "this-and-future") {
    property.setParameter("range", "THISANDFUTURE");
    return;
  }
  property.removeParameter("range");
}

/**
 * Assert the change's values on one component, leaving everything else alone.
 *
 * `DTSTART` and `DTEND` are REMOVED and re-added rather than updated in place,
 * because the update helper keeps the existing property's parameters and the
 * two ends may be changing their anchoring entirely — a timed occurrence made
 * all-day must lose its `TZID`, and an all-day one made timed must gain one.
 * Updating would leave the old parameter beside the new value.
 *
 * A null location or description REMOVES the property. That is the same claim
 * the tool boundary's own absent-versus-null rule makes one layer up: absent
 * means leave it, null means take it away — and by the time a change reaches
 * here every optional field has already been resolved to one or the other.
 */
function applyOverrideChange(
  component: IcalComponent,
  change: OverrideChange,
  sequence: number,
): void {
  component.updatePropertyWithValue(
    "dtstamp",
    utcTimeAt(Math.floor(Date.now() / 1000)),
  );
  component.updatePropertyWithValue("sequence", sequence);
  component.updatePropertyWithValue("summary", change.summary);
  setOrRemove(component, "location", change.location);
  setOrRemove(component, "description", change.description);

  component.removeAllProperties("dtstart");
  component.removeAllProperties("dtend");
  component.addProperty(anchoredTime("dtstart", change.startLocal, change));
  component.addProperty(anchoredTime("dtend", change.endLocal, change));

  setAlarms(component, change.alarms);
}

/**
 * Assert a reminder list on one component, or leave every stored one alone.
 *
 * **This is the whole of CALM-02, and it covers every scope because there is
 * only one place to put it.** All three patch writers converge on
 * `applyOverrideChange` above — `applyEventChange` for a resource that does not
 * repeat, and both arms of `applyOccurrenceOverride` for one that does — so a
 * scopeless update, an occurrence-scoped one and a this-and-future one cannot
 * disagree about alarms. There is no per-scope alarm code that could.
 *
 * `undefined` touches nothing, which is D-04's absent arm and the reason an
 * update that says nothing about reminders keeps the one the user set. Anything
 * else replaces the whole list, so `[]` removes every alarm.
 *
 * **The name is ALWAYS passed to `removeAllSubcomponents`, and what that buys is
 * narrower than it first looks — which is why it is written down rather than
 * inherited.** The plan for this work said the bare form "would take every
 * `VTIMEZONE` with it". That is true of
 * `serializeOccurrenceResource`'s own call, which operates on the `VCALENDAR`
 * where the zone definitions live. It is FALSE here: this operates on a
 * `VEVENT`, and a `VTIMEZONE` is never inside one. Recorded as having been wrong
 * rather than quietly restated, because a reason that overclaims is a reason the
 * next reader stops believing.
 *
 * What the name actually protects is every OTHER subcomponent a `VEVENT` can
 * carry, and that set is not empty on a real calendar:
 * `X-APPLE-STRUCTURED-LOCATION` is a component Apple Calendar writes inside a
 * `VEVENT` to hold a geocoded place, and RFC 9074 defines more `VALARM`-adjacent
 * structure. The bare form takes all of it, the resource still serialises, and
 * the user's event quietly loses its map pin because they changed a reminder.
 * Measured, and pinned by "removes ONLY the alarms, and leaves a foreign
 * subcomponent standing" in `test/dav-icalendar.test.ts` — the bare form passed
 * every other case in the suite, which is exactly the shape of gap a rule
 * believed on inherited prose leaves behind.
 *
 * **Nothing branches on the return value.** In `ical.js@2.2.1` that method
 * returns `undefined` regardless of what it removed, despite the JSDoc at
 * `node_modules/ical.js/lib/ical/component.js:472` promising a boolean —
 * measured by running it. A before-and-after count through
 * `getAllSubcomponents("valarm").length` is the only honest way to ask.
 */
function setAlarms(
  component: IcalComponent,
  alarms: AlarmSpec[] | undefined,
): void {
  if (alarms === undefined) return;

  component.removeAllSubcomponents("valarm");
  for (const spec of alarms) component.addSubcomponent(buildAlarm(spec));
}

/** Set a property to a value, or take it away entirely when the value is null. */
function setOrRemove(
  component: IcalComponent,
  name: string,
  value: string | null,
): void {
  if (value === null) {
    component.removeAllProperties(name);
    return;
  }
  component.updatePropertyWithValue(name, value);
}
