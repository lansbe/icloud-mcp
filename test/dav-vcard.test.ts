// CONT-01 (the empty formatted name) and CONT-02 (full contact detail).
//
// Pure, like `test/dav-icalendar.test.ts` beside it: a literal string goes in
// and a plain object comes out, with nothing stood up and no credential in this
// file's world. Which is what lets CONT-02 be asserted at all under D-09's rule
// that no automated job may authenticate against the real Apple ID.

import { describe, expect, it } from "vitest";
import { DavConnectError } from "../src/dav/errors";
import type { ContactName, ParsedContact } from "../src/dav/vcard";
import { displayNameFor, parseVCard } from "../src/dav/vcard";
import {
  EMPTY_FORMATTED_NAME_DISPLAY,
  EMPTY_FORMATTED_NAME_VCF,
  FULL_CONTACT_NOTE,
  FULL_CONTACT_VCF,
  GROUPED_LABEL_VCF,
  MALFORMED_VCF,
  NAMELESS_VCF,
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
