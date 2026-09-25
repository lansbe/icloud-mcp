// CONT-01 (the empty formatted name), CONT-02 (full contact detail), and
// CONW-03 / the synthetic half of CONW-04 (the round-trip fidelity proof, which
// has its own block and its own header comment further down).
//
// Pure, like `test/dav-icalendar.test.ts` beside it: a literal string goes in
// and a plain object comes out, with nothing stood up and no credential in this
// file's world. Which is what lets CONT-02 be asserted at all under D-09's rule
// that no automated job may authenticate against the real Apple ID.

import ICAL from "ical.js";
import { describe, expect, it } from "vitest";
import type { NormalizedContactChange } from "../src/confirm";
import { DavConnectError } from "../src/dav/errors";
import type { ContactName, ParsedContact } from "../src/dav/vcard";
import { displayNameFor, parseVCard, patchContactCard } from "../src/dav/vcard";
// Named imports for the cases that assert against one card, and a NAMESPACE
// import for the fidelity loop, which discovers its cards by name so a fixture
// added later is enrolled without anybody editing a list here.
import * as fixtures from "./fixtures/dav-bytes";
import {
  EMPTY_FORMATTED_NAME_DISPLAY,
  EMPTY_FORMATTED_NAME_VCF,
  FULL_CONTACT_NOTE,
  FULL_CONTACT_VCF,
  GROUPED_LABEL_VCF,
  MALFORMED_VCF,
  NAMELESS_VCF,
  ROUND_TRIP_HAZARDS_VCF,
  SINGLE_TYPE_PARAMETER_VCF,
} from "./fixtures/dav-bytes";

/** A contact with nothing on it, for the cases that exercise one field. */
const BLANK: ParsedContact = {
  uid: null,
  formattedName: null,
  name: null,
  organisation: [],
  address: null,
  note: null,
  emails: [],
  tels: [],
};

describe("a full card reads back with every field CONT-02 names", () => {
  const contact = parseVCard(FULL_CONTACT_VCF);

  it("reads the formatted name, the note, and the unique identifier", () => {
    expect(contact.formattedName).toBe("Dr. Marisol Q Solano PhD");
    expect(contact.note).toBe(FULL_CONTACT_NOTE);
    expect(contact.uid).toBe("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
  });

  it("reads the structured name as its five positional components", () => {
    expect(contact.name).toEqual({
      family: "Solano",
      given: "Marisol",
      additional: "Quill",
      prefix: "Dr.",
      suffix: "PhD",
    });
  });

  it("reads the organisation's components in order", () => {
    expect(contact.organisation).toEqual([
      "Example Manufacturing",
      "Reliability Engineering",
    ]);
  });

  it("reads the address positionally, with an empty component as absent", () => {
    // The library returns a plain array with empty strings for absent
    // components — no wrapper object. Indexing by position and reading `""` as
    // absent is the whole contract, and getting it wrong shifts every field
    // after the gap.
    expect(contact.address).toEqual({
      poBox: null,
      extended: null,
      street: "1 Example Way",
      locality: "Example City",
      region: "EX",
      postalCode: "00000",
      country: "Exampleland",
    });
  });

  it("reads EVERY email address, not just the first", () => {
    expect(contact.emails).toEqual([
      {
        value: "marisol@example.invalid",
        types: ["INTERNET", "HOME", "pref"],
        group: null,
      },
      {
        value: "marisol.solano@work.example.invalid",
        types: ["INTERNET", "WORK"],
        group: null,
      },
    ]);
  });

  it("reads EVERY telephone number, not just the first", () => {
    expect(contact.tels).toEqual([
      { value: "+1-555-0100", types: ["CELL", "VOICE", "pref"], group: null },
      { value: "+1-555-0199", types: ["HOME", "VOICE"], group: null },
    ]);
  });

  it("uses the formatted name as the display name when it has one", () => {
    expect(displayNameFor(contact)).toBe("Dr. Marisol Q Solano PhD");
  });
});

describe("a type parameter is normalised however many the property carries", () => {
  it("gives a single type parameter an array of length one", () => {
    // THE discriminating case. The accessor hands back a bare string here and
    // an array everywhere else, so mapping over it without normalising yields
    // the string's CHARACTERS — silently wrong rather than an error.
    const contact = parseVCard(SINGLE_TYPE_PARAMETER_VCF);
    expect(contact.emails[0]?.types).toEqual(["INTERNET"]);
    expect(contact.tels[0]?.types).toEqual(["CELL"]);
  });

  it("does not split a single type parameter into characters", () => {
    const types = parseVCard(SINGLE_TYPE_PARAMETER_VCF).emails[0]?.types ?? [];
    expect(types).toHaveLength(1);
    expect(types).not.toContain("I");
  });

  it("keeps several type parameters as several", () => {
    const contact = parseVCard(FULL_CONTACT_VCF);
    expect(contact.emails[0]?.types).toHaveLength(3);
    expect(contact.tels[1]?.types).toEqual(["HOME", "VOICE"]);
  });
});

describe("Apple's item-group prefix survives the parse", () => {
  const contact = parseVCard(GROUPED_LABEL_VCF);

  it("reads the group off a grouped property", () => {
    // The surface a dedicated vCard dependency was feared to be needed for.
    // D-63 removed that dependency on the strength of this working.
    expect(contact.emails[0]?.group).toBe("item1");
    expect(contact.tels[0]?.group).toBe("item2");
  });

  it("reports null for a property that carries no group", () => {
    // Without this the group could be invented rather than read, and every
    // assertion above would still pass.
    expect(contact.tels[1]?.group).toBeNull();
    expect(contact.tels[1]?.value).toBe("+1-555-0177");
  });

  it("does not drop a grouped property from the list", () => {
    // The failure this fixture actually guards against: a parser that ignored
    // grouped properties would lose the numbers Apple attaches custom labels
    // to, which are precisely the ones a person bothered to label.
    expect(contact.tels).toHaveLength(2);
    expect(contact.emails).toHaveLength(1);
  });
});

describe("a contact iCloud returned with an empty formatted name is still named", () => {
  it("falls back to the structured name", () => {
    // Apple's own developer forums document iCloud CardDAV returning cards with
    // an empty FN while N is populated, inconsistently across resyncs, on
    // contacts that display correctly in the iCloud web app and on iPhone.
    const contact = parseVCard(EMPTY_FORMATTED_NAME_VCF);
    expect(contact.formattedName).toBe("");
    expect(displayNameFor(contact)).toBe(EMPTY_FORMATTED_NAME_DISPLAY);
  });

  it("orders the fallback as Given Family", () => {
    const contact = parseVCard(EMPTY_FORMATTED_NAME_VCF);
    expect(contact.name).toEqual({
      family: "Okonkwo",
      given: "Adaeze",
      additional: null,
      prefix: null,
      suffix: null,
    });
    expect(displayNameFor(contact)).toBe("Adaeze Okonkwo");
  });

  it("drops an absent component rather than leaving a stray space", () => {
    const familyOnly = { ...BLANK, name: NAME_OF("", "Okonkwo") };
    const givenOnly = { ...BLANK, name: NAME_OF("Adaeze", "") };
    expect(displayNameFor(familyOnly)).toBe("Okonkwo");
    expect(displayNameFor(givenOnly)).toBe("Adaeze");
  });

  it("prefers a formatted name that is only whitespace no more than an empty one", () => {
    // A blank-looking name is a blank name to a reader, and the fallback exists
    // so a real address book never shows one.
    const blankish = { ...BLANK, formattedName: "   ", name: NAME_OF("Adaeze", "Okonkwo") };
    expect(displayNameFor(blankish)).toBe("Adaeze Okonkwo");
  });

  it("returns the formatted name VERBATIM when it is not blank", () => {
    // Untrusted text is reported, never rewritten. Trimming for the emptiness
    // decision must not become trimming of the value.
    const padded = { ...BLANK, formattedName: " Marisol Solano " };
    expect(displayNameFor(padded)).toBe(" Marisol Solano ");
  });

  it("yields an empty display name for a card with no name of either kind", () => {
    // The floor. An address book imported from autocomplete history is full of
    // these, and one of them must not be able to fail a whole page of contacts.
    const contact = parseVCard(NAMELESS_VCF);
    expect(contact.formattedName).toBeNull();
    expect(contact.name).toBeNull();
    expect(displayNameFor(contact)).toBe("");
    expect(contact.emails[0]?.value).toBe("anonymous@example.invalid");
  });
});

describe("parsing is a pure function of the bytes", () => {
  it("returns an equal object for equal input", () => {
    expect(parseVCard(FULL_CONTACT_VCF)).toEqual(parseVCard(FULL_CONTACT_VCF));
    expect(parseVCard(GROUPED_LABEL_VCF)).toEqual(parseVCard(GROUPED_LABEL_VCF));
  });

  it("leaves absent properties absent rather than inventing them", () => {
    const contact = parseVCard(NAMELESS_VCF);
    expect(contact.organisation).toEqual([]);
    expect(contact.address).toBeNull();
    expect(contact.note).toBeNull();
    expect(contact.tels).toEqual([]);
  });
});

describe("a body that is not a contact resource is refused, not half-read", () => {
  it("throws the DAV tree's own typed error", () => {
    expect(() => parseVCard(MALFORMED_VCF)).toThrow(DavConnectError);
  });

  it("refuses a calendar body arriving at the contact parser", () => {
    expect(() => parseVCard("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n"))
      .toThrow(DavConnectError);
  });
});

/** A structured name with only the two components the fallback reads. */
function NAME_OF(given: string, family: string): ContactName {
  return {
    family: family === "" ? null : family,
    given: given === "" ? null : given,
    additional: null,
    prefix: null,
    suffix: null,
  };
}

// ---------------------------------------------------------------------------
// CONW-03 and the synthetic half of CONW-04: the round-trip fidelity proof.
//
// PITFALLS #39 is the failure being guarded against. A contact update is a
// whole-vCard overwrite, so every property the outgoing bytes do not carry is
// DELETED from the account and from every device the user owns. `parseVCard`
// reads eight properties. The proof below is that `patchContactCard` does not
// lose the rest.
//
// **The proof is a full-string comparison of the whole card, and it stays one.**
// A field-by-field or property-set comparison can only check what its author
// already knew to list, and it would pass for a serialiser that dropped every
// property nobody had heard of. Worse, a set comparison misses a MANGLED value
// that stays the same property: `N:Family,Given,,,` is exactly that shape and
// plan 16-01 found it live.
//
// **Four normalisations are applied to both sides before the comparison, and
// each one is named, measured and justified individually.** Re-serialising a
// vCard through `ical.js` is lossless but NOT byte-identical: measured directly
// on 2026-09-24, every property returns with its group prefix and its full
// base64 payload intact, and exactly four things change. Comparing raw bytes
// would therefore halt the phase on run one for a reason that is a fact about
// the library rather than a defect. Comparing LOOSELY would buy nothing. So the
// four are absorbed by name and a FIFTH difference turns this suite red — which
// `the normalisation absorbs four differences and no fifth` below proves by
// running perturbed cards through the same normaliser and requiring each one to
// come out unequal.
// ---------------------------------------------------------------------------

/** A change that mentions nothing at all: every field at its outer null. */
const MENTIONS_NOTHING: NormalizedContactChange = {
  kind: "update",
  formattedName: null,
  name: null,
  organisation: null,
  address: null,
  note: null,
  emails: null,
  tels: null,
};

/**
 * Normalisation 1 of 4 — the fold points.
 *
 * Measured: the library re-folds a long value at its own column boundaries
 * rather than the hand-written ones. The photo's payload re-folds, and `NOTE`'s
 * trailing space moves from the head of the continuation line to the tail of
 * the line before it. Unfolding both sides removes the difference and keeps the
 * whole logical value, so nothing is hidden: a payload that LOST a byte still
 * comes out shorter.
 */
function unfoldContinuationLines(text: string): string {
  return text.replace(/\r\n[ \t]/g, "");
}

/**
 * Normalisation 2 of 4 — the case of the group prefix and the property name.
 *
 * Measured: `item1.X-ABLabel` comes back as `ITEM1.X-ABLABEL`. BOTH halves are
 * upper-cased, not only the prefix. RFC 6350 makes both case-insensitive, so
 * this is a spelling change and not a value change.
 *
 * Only the text before the FIRST `;` or `:` is touched — the name and its group
 * prefix, and nothing else. A parameter value and a property value keep their
 * case, which is what lets a lower-cased `TYPE=internet` register as a fifth
 * difference instead of being absorbed.
 */
function upperCaseNameAndGroup(line: string): string {
  const delimiter = line.search(/[;:]/);
  if (delimiter === -1) return line;
  return line.slice(0, delimiter).toUpperCase() + line.slice(delimiter);
}

/**
 * Normalisation 3 of 4 — repeated type parameters merging.
 *
 * Measured: `TYPE=INTERNET;TYPE=HOME` comes back as `TYPE=INTERNET,HOME`. Both
 * spellings are legal vCard 3.0 and carry the same value; one is being
 * exchanged for the other.
 *
 * Applied in the merging direction only, and case-sensitively on the parameter
 * name, so a parameter that changed NAME case or changed ORDER is not absorbed.
 * Looped to a fixed point because a property carrying three types needs two
 * merges.
 */
function mergeRepeatedTypeParameters(line: string): string {
  let merged = line;
  for (;;) {
    const next = merged.replace(/;TYPE=([^;:]+);TYPE=/g, ";TYPE=$1,");
    if (next === merged) return merged;
    merged = next;
  }
}

/**
 * Normalisation 4 of 4 — the trailing terminator.
 *
 * Measured: `Component#toString()` emits no CRLF after `END:VCARD`.
 * `patchContactCard` appends one, exactly as the calendar serialiser does, so
 * this step is an IDENTITY on both sides today rather than a difference being
 * absorbed. `the trailing terminator is discharged by the code, not by the
 * normalisation` below asserts that, so the step cannot quietly start carrying
 * weight.
 */
function oneTrailingTerminator(text: string): string {
  return `${text.replace(/(\r\n)+$/, "")}\r\n`;
}

/** The four, in order, applied to one side of the comparison. */
function normaliseForFidelity(text: string): string {
  const lines = unfoldContinuationLines(text)
    .split("\r\n")
    .map((line) => mergeRepeatedTypeParameters(upperCaseNameAndGroup(line)));
  return oneTrailingTerminator(lines.join("\r\n"));
}

/** A resource body, paired with the export name it came from. */
interface NamedCard {
  name: string;
  text: string;
}

/**
 * Every well-formed vCard fixture, discovered by NAME.
 *
 * The enrolment filter is `test/dav-fixtures.test.ts`'s, copied deliberately: a
 * fixture added later is enrolled in this proof by being named `*_VCF` and by
 * nothing else, so nobody has to remember to add it to a list here. The
 * discriminating case below guards the filter, because a filter that silently
 * stopped matching would make every case in this block pass vacuously.
 */
const WELL_FORMED_CARDS: NamedCard[] = Object.entries(fixtures)
  .filter(
    (entry): entry is [string, string] =>
      typeof entry[1] === "string" &&
      entry[0].endsWith("_VCF") &&
      !entry[0].startsWith("MALFORMED"),
  )
  .map(([name, text]) => ({ name, text }))
  .sort((a, b) => a.name.localeCompare(b.name));

describe("every well-formed card survives a no-op round trip", () => {
  it("enrols every card the fixture module names, so the loop cannot go vacuous", () => {
    // THE discriminating case for the whole block. A filter matching nothing
    // would turn the proof below into a loop over zero cards.
    expect(WELL_FORMED_CARDS.length).toBeGreaterThanOrEqual(6);
    expect(WELL_FORMED_CARDS.map((card) => card.name)).toContain(
      "ROUND_TRIP_HAZARDS_VCF",
    );
  });

  it.each(WELL_FORMED_CARDS.map((card) => [card.name, card.text] as const))(
    "%s comes back with every byte it went in with",
    (name, text) => {
      const out = patchContactCard(text, MENTIONS_NOTHING);
      const expected = normaliseForFidelity(text);
      const actual = normaliseForFidelity(out);
      expect(
        actual,
        firstDifferenceReport(name, expected, actual),
      ).toBe(expected);
    },
  );
});

describe("the trailing terminator is discharged by the code, not by the normalisation", () => {
  it.each(WELL_FORMED_CARDS.map((card) => [card.name, card.text] as const))(
    "%s already ends in exactly one CRLF on both sides",
    (_name, text) => {
      // Normalisation 4 must stay an identity. If it ever starts changing a
      // side, the serialiser's terminator behaviour moved and that is a
      // decision rather than something a normaliser should absorb silently.
      const out = patchContactCard(text, MENTIONS_NOTHING);
      expect(out.endsWith("END:VCARD\r\n")).toBe(true);
      expect(oneTrailingTerminator(out)).toBe(out);
      expect(oneTrailingTerminator(text)).toBe(text);
    },
  );
});

describe("the normalisation absorbs four differences and no fifth", () => {
  const CARD = ROUND_TRIP_HAZARDS_VCF;

  /** A difference that is NOT one of the four must survive normalisation. */
  function survivesNormalisation(perturbed: string): boolean {
    return normaliseForFidelity(perturbed) !== normaliseForFidelity(CARD);
  }

  it("does not absorb a changed value byte", () => {
    // The mangled-value shape a property-set comparison misses entirely.
    expect(survivesNormalisation(CARD.replace("Vaskez", "Vazkez"))).toBe(true);
  });

  it("does not absorb a dropped property", () => {
    expect(
      survivesNormalisation(CARD.replace("NOTE:Restores ledgers and asks for a fortnight of notice.\r\n", "")),
    ).toBe(true);
  });

  it("does not absorb a dropped byte from the photo's payload", () => {
    // The fold points are absorbed; the PAYLOAD is not. This is the case that
    // separates the two, and it is the one the photo hazard exists for.
    expect(survivesNormalisation(CARD.replace("VGhpcyBpcyBub3QgYW4g", "VGhpcyBpcyBub3QgYW4"))).toBe(true);
  });

  it("does not absorb a reordered parameter", () => {
    expect(
      survivesNormalisation(
        CARD.replace("PHOTO;ENCODING=b;TYPE=JPEG:", "PHOTO;TYPE=JPEG;ENCODING=b:"),
      ),
    ).toBe(true);
  });

  it("does not absorb a parameter VALUE whose case changed", () => {
    // Normalisation 2 upper-cases the NAME and the group prefix only. A value
    // is data, and a serialiser that re-cased one changed the card.
    expect(
      survivesNormalisation(CARD.replace("TYPE=INTERNET:noor@", "TYPE=internet:noor@")),
    ).toBe(true);
  });

  it("does not absorb a changed item-group number", () => {
    // `ITEM1.EMAIL` with `ITEM1.X-ABLABEL` is a pair. Renumbering one half
    // breaks the label's binding, which is the grouped-label hazard itself.
    expect(survivesNormalisation(CARD.replace("item1.X-ABLabel", "item2.X-ABLabel"))).toBe(true);
  });

  it("does not absorb an added property", () => {
    expect(
      survivesNormalisation(CARD.replace("END:VCARD", "X-ADDED-BY-SOMETHING:1\r\nEND:VCARD")),
    ).toBe(true);
  });
});

describe("serialisation is a fixed point", () => {
  it.each(WELL_FORMED_CARDS.map((card) => [card.name, card.text] as const))(
    "%s re-serialises to itself the second time, byte for byte",
    (_name, text) => {
      // Independent of the no-op proof above, and RAW rather than normalised:
      // both sides here are the library's own output, so there is nothing to
      // normalise. It holds even if the library re-frames a hand-authored card
      // on first contact, which is what makes it the case distinguishing "the
      // serialiser normalised the input" from "the serialiser lost something".
      const once = patchContactCard(text, MENTIONS_NOTHING);
      const twice = patchContactCard(once, MENTIONS_NOTHING);
      expect(twice).toBe(once);
    },
  );

  it("applies the same real change twice to the same bytes", () => {
    // CONW-03's idempotency claim over a change that actually changes
    // something. It holds because nothing here writes a revision stamp, a
    // product identifier or a timestamp of its own.
    const change: NormalizedContactChange = {
      ...MENTIONS_NOTHING,
      note: { value: "Rebound a ledger in March." },
    };
    const first = patchContactCard(ROUND_TRIP_HAZARDS_VCF, change);
    const second = patchContactCard(ROUND_TRIP_HAZARDS_VCF, change);
    expect(second).toBe(first);
  });
});

describe("the property multiset is the diagnosis, not the proof", () => {
  // This walks the CARD'S OWN property list rather than a list of fields
  // somebody chose, which is the opposite of the comparison the block above
  // forbids. Its job is to turn a failing byte comparison into a diagnosis:
  //
  //   equal multiset + unequal bytes  -> the serialiser RE-FRAMED the card,
  //                                      and nothing was lost.
  //   unequal multiset                -> a property, a parameter or a group
  //                                      prefix was DROPPED, which is the
  //                                      PITFALLS #39 failure itself.
  //
  // It is never the proof, because a multiset cannot see a value mangled inside
  // a property that is still present.
  it.each(WELL_FORMED_CARDS.map((card) => [card.name, card.text] as const))(
    "%s carries the same properties, parameters and group prefixes afterwards",
    (_name, text) => {
      const out = patchContactCard(text, MENTIONS_NOTHING);
      expect(propertyMultiset(out)).toEqual(propertyMultiset(text));
    },
  );
});

describe("a patch moves what the change named and nothing else", () => {
  const NO_OP = patchContactCard(ROUND_TRIP_HAZARDS_VCF, MENTIONS_NOTHING);

  it("changes exactly one line when one text field changes", () => {
    const patched = patchContactCard(ROUND_TRIP_HAZARDS_VCF, {
      ...MENTIONS_NOTHING,
      note: { value: "Rebound a ledger in March." },
    });
    const before = NO_OP.split("\r\n");
    const after = patched.split("\r\n");
    expect(after).toHaveLength(before.length);
    const moved = before
      .map((line, index) => [line, after[index]] as const)
      .filter(([left, right]) => left !== right);
    expect(moved).toEqual([
      [
        "NOTE:Restores ledgers and asks for a fortnight of notice.",
        "NOTE:Rebound a ledger in March.",
      ],
    ]);
  });

  it("leaves the photo, the grouped label pair and the unmodelled property alone", () => {
    const patched = unfoldContinuationLines(
      patchContactCard(ROUND_TRIP_HAZARDS_VCF, {
        ...MENTIONS_NOTHING,
        note: { value: "Rebound a ledger in March." },
      }),
    );
    // The three hazards CONW-04 names, each asserted by its own bytes.
    expect(patched).toContain(
      "VGhpcyBpcyBub3QgYW4gaW1hZ2UuIEl0IGlzIGEgYmFzZTY0IHNoYXBlZCBwYXlsb2FkLCBoYW5kIHBpY2tlZCBzbyB0aGF0IG5vIHBsdXMgY2hhcmFjdGVyIGFuZCBubyBsb25nIGRpZ2l0IHJ1biByZWFjaGVzIHRoZSBmaXh0dXJlIHJ1bGVzLiBEZWNvZGUgaXQgYW5kIHlvdSBnZXQgdGhpcyBzZW50ZW5jZS4=",
    );
    expect(patched).toContain("ITEM1.EMAIL;TYPE=INTERNET:noor@example.invalid");
    expect(patched).toContain("ITEM1.X-ABLABEL:Studio");
    expect(patched).toContain("X-PHONETIC-LAST-NAME:Vaskez");
    // The revision the CARD carried survives. Nothing here writes one.
    expect(patched).toContain("REV:20260106T000000Z");
  });

  it("carries no removed entry's TYPE parameter or group prefix onto a new email", () => {
    const patched = patchContactCard(ROUND_TRIP_HAZARDS_VCF, {
      ...MENTIONS_NOTHING,
      emails: [{ value: "bindery@example.invalid", types: ["WORK"] }],
    });
    const emailLines = patched
      .split("\r\n")
      .filter((line) => /EMAIL/i.test(line));
    // Exactly one email, and it is the supplied one with the supplied type.
    expect(emailLines).toEqual(["EMAIL;TYPE=WORK:bindery@example.invalid"]);
    // Named individually, because each is a separate way the corruption lands.
    expect(patched).not.toContain("TYPE=INTERNET");
    expect(patched).not.toContain("TYPE=HOME");
    expect(patched).not.toContain("ITEM1.EMAIL");
    expect(patched).not.toContain("item1.EMAIL");
    expect(patched).not.toMatch(/^ITEM\d+\.EMAIL/im);
  });

  it("leaves the telephone numbers untouched when only the emails are replaced", () => {
    const patched = patchContactCard(ROUND_TRIP_HAZARDS_VCF, {
      ...MENTIONS_NOTHING,
      emails: [{ value: "bindery@example.invalid", types: ["WORK"] }],
    });
    expect(patched).toContain("TEL;TYPE=CELL,VOICE:+1-555-0188");
  });

  it("leaves an orphaned Apple label standing rather than deleting a property nobody named", () => {
    // Deliberate, argued in `patchContactCard`'s docstring, and asserted here
    // so it is a recorded behaviour rather than an accident: the label is a
    // property the change did not mention, and this server deleting an
    // unmentioned property is the failure the whole function exists to avoid.
    const patched = patchContactCard(ROUND_TRIP_HAZARDS_VCF, {
      ...MENTIONS_NOTHING,
      emails: [{ value: "bindery@example.invalid", types: ["WORK"] }],
    });
    expect(patched).toContain("ITEM1.X-ABLABEL:Studio");
  });

  it("removes a property when the change clears it explicitly", () => {
    const patched = patchContactCard(ROUND_TRIP_HAZARDS_VCF, {
      ...MENTIONS_NOTHING,
      note: { value: null },
    });
    expect(patched).not.toMatch(/^NOTE/im);
    // And nothing else moved with it.
    expect(patched.split("\r\n")).toHaveLength(NO_OP.split("\r\n").length - 1);
  });

  it("writes the structured name with the structured separator, never the multi-value one", () => {
    // 16-01's live trap: `setValues` emits `N:Family,Given,,,`, which round
    // trips through this library perfectly and is read by Apple as one family
    // name containing three commas. A multiset comparison cannot see it.
    const patched = patchContactCard(ROUND_TRIP_HAZARDS_VCF, {
      ...MENTIONS_NOTHING,
      name: {
        family: "Vasquez-Ruiz",
        given: "Noor",
        additional: null,
        prefix: null,
        suffix: null,
      },
    });
    expect(patched).toContain("N:Vasquez-Ruiz;Noor;;;");
    expect(patched).not.toContain("N:Vasquez-Ruiz,Noor");
  });

  it("moves nothing at all when the change mentions nothing", () => {
    expect(patchContactCard(ROUND_TRIP_HAZARDS_VCF, MENTIONS_NOTHING)).toBe(NO_OP);
  });
});

describe("an empty formatted name is still present and still empty afterwards", () => {
  it("keeps FN as a present, empty property through a no-op round trip", () => {
    // The empty string and absence are different facts on this property, and
    // iCloud produces the first one. A round trip that "tidied" the empty FN
    // away would change what the card says about itself.
    const out = patchContactCard(EMPTY_FORMATTED_NAME_VCF, MENTIONS_NOTHING);
    expect(out).toMatch(/^FN:\r$/m);
    expect(parseVCard(out).formattedName).toBe("");
  });
});

/**
 * Every property on a card, as a sortable signature.
 *
 * The group prefix is upper-cased for normalisation 2's reason and nothing else
 * is touched, so a value whose case changed still shows up as a difference.
 */
function propertyMultiset(vcfText: string): string[] {
  const card = new ICAL.Component(ICAL.parse(vcfText));
  return card
    .getAllProperties()
    .map((property) => {
      const parameters = Object.entries(property.toJSON()[1] as Record<string, unknown>)
        .map(([key, value]) => {
          const text = Array.isArray(value) ? value.join(",") : String(value);
          return `${key.toLowerCase()}=${key.toLowerCase() === "group" ? text.toUpperCase() : text}`;
        })
        .sort();
      return `${property.name}|${parameters.join(";")}|${JSON.stringify(property.getValues())}`;
    })
    .sort();
}

/**
 * The first byte at which two cards diverge, with the text either side.
 *
 * A failing fidelity case is the phase's halt gate, and the owner needs the
 * actual difference rather than the fact of one: a card that does not come back
 * identical is a card whose properties this server would destroy on the user's
 * phone, and which property was lost decides what happens next.
 */
function firstDifferenceReport(name: string, expected: string, actual: string): string {
  let offset = 0;
  while (offset < expected.length && offset < actual.length && expected[offset] === actual[offset]) {
    offset += 1;
  }
  const window = 60;
  const from = Math.max(0, offset - 20);
  return [
    `${name} did not survive a no-op round trip.`,
    "A card that does not come back identical is a card whose properties this",
    "server would DESTROY on the user's phone and on every other device they own.",
    `First difference at byte ${offset} of ${expected.length}.`,
    `  fetched: ${JSON.stringify(expected.slice(from, from + window))}`,
    `  written: ${JSON.stringify(actual.slice(from, from + window))}`,
  ].join("\n");
}
