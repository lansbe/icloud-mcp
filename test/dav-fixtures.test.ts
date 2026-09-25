// Fixture integrity for `test/fixtures/dav-bytes.ts`.
//
// Those fixtures are SYNTHESISED, not captured — the decision and its reasons
// are in that file's header and in 02-09-SUMMARY.md. Synthesis makes this file
// necessary rather than optional: bytes that came off a real server are at
// least self-consistent by construction, while bytes someone typed are only as
// correct as the assertions holding them to it.
//
// So these cases hold the fixtures to four things:
//
//   1. They parse. A fixture that `ICAL.parse` rejects would fail every test
//      built on it for a reason that has nothing to do with the parser under
//      test, and the two malformed fixtures are asserted to throw for the same
//      reason in reverse — a "malformed" fixture that quietly parses proves
//      nothing about the refusal path it exists for.
//   2. Their folded lines say what the exported constants claim. A fold typed
//      by hand is exactly the kind of thing a later test inherits a typo from.
//   3. Their framing is CRLF, which is what both formats define and what the
//      library is being trusted to handle.
//   4. They contain nothing account-identifying. That is a standing constraint
//      on anything added to the fixture file later, which makes it worth an
//      executable check rather than a comment nobody re-reads.
//
// Every case WALKS the fixture module's exports rather than naming them, so a
// fixture added next month without an assertion of its own is still held to all
// four. The walk itself is guarded: the set it finds must equal the set of
// exports whose names say they are resources, so a filter that silently stopped
// matching would fail rather than pass vacuously.

import ICAL from "ical.js";
import { describe, expect, it } from "vitest";
import * as fixtures from "./fixtures/dav-bytes";

/** A resource body, paired with the export name it came from. */
interface NamedFixture {
  name: string;
  text: string;
}

/** Every exported string that looks like a resource body. */
const ALL: NamedFixture[] = Object.entries(fixtures)
  .filter(
    (entry): entry is [string, string] =>
      typeof entry[1] === "string" && entry[1].includes("BEGIN:"),
  )
  .map(([name, text]) => ({ name, text }))
  .sort((a, b) => a.name.localeCompare(b.name));

/** The fixtures that are supposed to parse — everything but the two garbage ones. */
const WELL_FORMED = ALL.filter((f) => !f.name.startsWith("MALFORMED"));

/** The fixtures that are supposed to be rejected. */
const MALFORMED = ALL.filter((f) => f.name.startsWith("MALFORMED"));

describe("the walk sees every fixture, so a new one cannot slip past", () => {
  it("finds exactly the exports whose names say they are resources", () => {
    // THE discriminating case for every other test in this file. A filter that
    // matched nothing would make all of them pass, and pass silently.
    const byName = Object.keys(fixtures)
      .filter((name) => name.endsWith("_ICS") || name.endsWith("_VCF"))
      .sort();
    expect(ALL.map((f) => f.name)).toEqual(byName);
    expect(ALL.length).toBeGreaterThanOrEqual(14);
  });

  it("covers both formats and both outcomes", () => {
    expect(ALL.filter((f) => f.name.endsWith("_ICS")).length).toBeGreaterThanOrEqual(8);
    expect(ALL.filter((f) => f.name.endsWith("_VCF")).length).toBeGreaterThanOrEqual(6);
    expect(MALFORMED.length).toBe(2);
  });
});

describe("the fixtures drive the real parser", () => {
  it.each(WELL_FORMED.map((f) => [f.name, f.text] as const))(
    "%s parses",
    (_name, text) => {
      expect(() => ICAL.parse(text)).not.toThrow();
    },
  );

  it.each(MALFORMED.map((f) => [f.name, f.text] as const))(
    "%s is rejected rather than half-read",
    (_name, text) => {
      expect(() => ICAL.parse(text)).toThrow();
    },
  );

  it("frames every fixture with CRLF, as both formats define", () => {
    for (const { name, text } of ALL) {
      expect(text, name).toContain("\r\n");
      // A bare LF anywhere would mean the fixture is testing a leniency of the
      // parser rather than the format the server actually speaks.
      expect(/[^\r]\n/.test(text), name).toBe(false);
      expect(text.endsWith("\r\n"), name).toBe(true);
    }
  });
});

describe("the hand-typed folds say what the constants claim", () => {
  // Fixture integrity, not a parser claim: these prove the continuation lines
  // written into the fixture actually unfold to the exported expectations, so a
  // later plan asserting against those constants is not inheriting a typo.
  it("unfolds the calendar description across its continuation line", () => {
    const vcal = new ICAL.Component(
      ICAL.parse(fixtures.WEEKLY_SERIES_WITH_OVERRIDE_ICS),
    );
    const master = vcal
      .getAllSubcomponents("vevent")
      .find((v) => !v.hasProperty("recurrence-id"));
    expect(master?.getFirstPropertyValue("description")).toBe(
      fixtures.WEEKLY_SERIES_DESCRIPTION,
    );
  });

  it("unfolds the contact note across its continuation line", () => {
    const card = new ICAL.Component(ICAL.parse(fixtures.FULL_CONTACT_VCF));
    expect(card.getFirstPropertyValue("note")).toBe(fixtures.FULL_CONTACT_NOTE);
  });

  it("keeps at least one real fold in each format", () => {
    // Without this the two cases above could be satisfied by deleting the fold
    // and shortening the constant, which would quietly retire the only coverage
    // this project has of the thing it adopted a real parser to avoid
    // hand-rolling.
    const folded = (text: string) => /\r\n[ \t]/.test(text);
    expect(folded(fixtures.WEEKLY_SERIES_WITH_OVERRIDE_ICS)).toBe(true);
    expect(folded(fixtures.FULL_CONTACT_VCF)).toBe(true);
  });
});

describe("the round-trip card is still hazardous, not merely still safe", () => {
  // Every rule in this file proves a fixture is SAFE to commit. Nothing above
  // proves `ROUND_TRIP_HAZARDS_VCF` is still DANGEROUS, and that is the only
  // property CONW-04's fidelity proof buys anything from. A card that lost its
  // photo would sail through all nine rules while quietly retiring the coverage
  // the proof rests on — the same argument "keeps at least one real fold in each
  // format" makes about itself, applied to three more properties.
  //
  // The eight properties `parseVCard` reads (`src/dav/vcard.ts`), written out
  // LITERALLY rather than derived from the parser. Deriving them would make the
  // unmodelled-property case vacuous the day a ninth is added: the parser would
  // grow, the fixture's extension property would become modelled, and the case
  // would still pass while proving nothing.
  const MODELLED_BY_PARSE_VCARD = [
    "uid",
    "fn",
    "n",
    "org",
    "adr",
    "note",
    "email",
    "tel",
  ];

  it("still carries a base64 photo folded across a continuation line", () => {
    // The photo property plus every continuation line belonging to it. The fold
    // has to be inside THAT span: a fold anywhere else in the card would satisfy
    // a whole-text check while the photo sat on one line.
    const span = /\r\nPHOTO;[^\r\n]*\r\n(?:[ \t][^\r\n]*\r\n)*/.exec(
      fixtures.ROUND_TRIP_HAZARDS_VCF,
    );
    expect(
      span,
      "ROUND_TRIP_HAZARDS_VCF has lost its PHOTO property. That was the " +
        "multi-line folded-value hazard, and CONW-04's fidelity proof runs " +
        "against this card precisely because a hand-rolled serialiser destroys " +
        "it. Restore it rather than adjusting this case.",
    ).not.toBeNull();
    const photo = span?.[0] ?? "";
    expect(
      /ENCODING=b\b/i.test(photo),
      "ROUND_TRIP_HAZARDS_VCF's PHOTO is no longer in the inline base64 form. " +
        "A photo held by reference is not the hazard: the bytes are what a " +
        "whole-card overwrite drops.",
    ).toBe(true);
    // `.slice(2)` drops the leading CRLF the match starts with, so only a real
    // continuation line inside the photo can satisfy this.
    expect(
      /\r\n[ \t]/.test(photo.slice(2)),
      "ROUND_TRIP_HAZARDS_VCF's PHOTO no longer folds across a continuation " +
        "line. An unfolded photo retires the only coverage this project has of " +
        "the folded-value case, which is the thing it adopted a real parser for.",
    ).toBe(true);
  });

  it("still pairs a grouped address with an Apple label under the same group prefix", () => {
    const card = fixtures.ROUND_TRIP_HAZARDS_VCF;
    const groupsWith = (property: string) =>
      new Set(
        [
          ...card.matchAll(
            new RegExp(`\\r\\n(item\\d+)\\.${property}[;:]`, "gi"),
          ),
        ].map((match) => (match[1] ?? "").toLowerCase()),
      );
    const addressGroups = groupsWith("EMAIL");
    const labelGroups = groupsWith("X-ABLabel");
    const shared = [...addressGroups].filter((group) => labelGroups.has(group));
    expect(
      shared,
      "ROUND_TRIP_HAZARDS_VCF no longer has an item-group address and an " +
        "X-ABLabel sharing one prefix. The shared prefix is the ONLY thing " +
        "binding Apple's custom label to the address it names, and whole-list " +
        "replacement of emails is the write this phase ships that is most " +
        "likely to break it. Both properties existing separately is not the " +
        "hazard; sharing a prefix is.",
    ).not.toHaveLength(0);
  });

  it("still carries an extension property this project's parser cannot see", () => {
    const card = new ICAL.Component(
      ICAL.parse(fixtures.ROUND_TRIP_HAZARDS_VCF),
    );
    const unmodelled = card
      .getAllProperties()
      .map((property) => property.name.toLowerCase())
      .filter(
        (name) =>
          name.startsWith("x-") &&
          !MODELLED_BY_PARSE_VCARD.includes(name) &&
          // X-ABLabel is already pinned by the grouped-label case above.
          // Excluding it keeps this hazard independent: deleting the phonetic
          // property must fail HERE and not be covered for free by the label.
          name !== "x-ablabel",
      );
    expect(
      unmodelled,
      "ROUND_TRIP_HAZARDS_VCF no longer carries an extension property outside " +
        "the eight `parseVCard` reads, other than the grouped label. That " +
        "property's entire job is to be invisible to this project's parser and " +
        "survive a write anyway, which is the failure PITFALLS #39 names: a " +
        "contact update is a whole-vCard overwrite and it drops the fields the " +
        "reader never showed you.",
    ).not.toHaveLength(0);
  });
});

describe("the undefined zone is undefined everywhere, not just locally", () => {
  it("is named as a parameter and defined by no fixture", () => {
    // `ICAL.TimezoneService` is process-global. If any fixture in this file
    // DEFINED Australia/Sydney, whichever test parsed it first would register
    // the zone for the whole isolate and the unresolved-timezone case would
    // resolve — turning a correctness assertion into a test-ordering assertion.
    const definitionLine = `TZID:${fixtures.UNDEFINED_TZID}`;
    const parameterUse = `TZID=${fixtures.UNDEFINED_TZID}`;
    expect(ALL.some((f) => f.text.includes(parameterUse))).toBe(true);
    for (const { name, text } of ALL) {
      expect(text.includes(definitionLine), name).toBe(false);
    }
  });

  it("defines the zone the recurring fixtures are read against", () => {
    expect(fixtures.WEEKLY_SERIES_WITH_OVERRIDE_ICS).toContain(
      `TZID:${fixtures.DEFINED_TZID}`,
    );
    expect(fixtures.DEFINED_TZID).not.toBe(fixtures.UNDEFINED_TZID);
  });
});

describe("the zone table is held to the same rules as the resources", () => {
  // `VTIMEZONE_BLOCKS` is a Record rather than a string, so the walk above
  // cannot see it — the filter is `typeof entry[1] === "string"`. It is fixture
  // bytes all the same: it ships inside every resource this server writes, and
  // "a standing constraint on anything added later" has to mean the zone table
  // too, or the one export exempt from the privacy rules is the one that ends
  // up in the user's real calendar.
  const BLOCKS = Object.entries(fixtures.VTIMEZONE_BLOCKS);

  it("is non-empty, so the cases below are not passing over nothing", () => {
    expect(BLOCKS.length).toBeGreaterThan(0);
  });

  it.each(BLOCKS)("%s parses and frames with CRLF", (name, text) => {
    expect(() => ICAL.parse(text)).not.toThrow();
    expect(/[^\r]\n/.test(text), name).toBe(false);
    expect(text.endsWith("\r\n"), name).toBe(true);
  });

  it("carries nothing account-identifying", () => {
    for (const [name, text] of BLOCKS) {
      expect(/https?:\/\//i.test(text), name).toBe(false);
      expect(/[\w.+-]+@[\w.-]+/.test(text), name).toBe(false);
      // A DSID is a long bare number. The longest legitimate run here is an
      // eight-digit anchor date.
      const longest = (text.match(/\d+/g) ?? []).reduce(
        (max, run) => Math.max(max, run.length),
        0,
      );
      expect(longest, name).toBeLessThan(9);
    }
  });
});

describe("nothing account-identifying is committed in the fixtures", () => {
  // A standing constraint on whatever gets added later, made executable. The
  // fixture-privacy decision turned on git history being permanent and one-way;
  // a check that only ran once, by hand, on the day the file was written
  // protects only the version that existed that day.
  it("uses only the reserved .invalid TLD for every address", () => {
    let seen = 0;
    for (const { name, text } of ALL) {
      for (const address of text.match(/[\w.+-]+@[\w.-]+/g) ?? []) {
        seen += 1;
        expect(address.endsWith(".invalid"), `${name}: ${address}`).toBe(true);
      }
    }
    expect(seen).toBeGreaterThan(0);
  });

  it("names no real mail or calendar provider", () => {
    for (const { name, text } of ALL) {
      const lowered = text.toLowerCase();
      for (const domain of ["icloud.com", "me.com", "mac.com", "apple.com"]) {
        expect(lowered.includes(domain), `${name}: ${domain}`).toBe(false);
      }
    }
  });

  it("carries no URL that could name a shard, a principal, or a host", () => {
    // The DAV analogue of the Received chain: a captured resource would carry
    // the account's own href, and the discovery layer exists precisely so the
    // resolved shard host never becomes visible.
    for (const { name, text } of ALL) {
      expect(/https?:\/\//i.test(text), name).toBe(false);
      expect(/\bp\d{1,3}-(?:cal|card)dav\b/i.test(text), name).toBe(false);
      expect(/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(text), name).toBe(false);
    }
  });

  it("dials nowhere: every telephone number is in the fictional block", () => {
    let seen = 0;
    for (const { name, text } of ALL) {
      for (const match of text.matchAll(/\+1-(\d{3})-(\d{4})/g)) {
        seen += 1;
        expect(match[1], name).toBe("555");
        expect(match[2]?.startsWith("01"), `${name}: ${match[0]}`).toBe(true);
      }
      // Anything phone-shaped that the fictional pattern did NOT match.
      expect(/\+\d[\d ().-]{9,}/.test(text.replace(/\+1-555-01\d\d/g, "")), name)
        .toBe(false);
    }
    expect(seen).toBeGreaterThan(0);
  });

  it("carries no digit run long enough to be a principal identifier", () => {
    // A DSID is a long bare number. Every legitimate run in these fixtures is a
    // date (eight digits) or a time (six), so nine is comfortably above the
    // format's own needs and below anything an account identifier fits in.
    for (const { name, text } of ALL) {
      const longest = (text.match(/\d+/g) ?? []).reduce(
        (max, run) => Math.max(max, run.length),
        0,
      );
      expect(longest, name).toBeLessThan(9);
    }
  });
});
