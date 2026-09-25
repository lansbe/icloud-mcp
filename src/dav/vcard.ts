// Pure vCard parsing, field extraction and serialisation, including the empty
// formatted-name fallback CONT-01 turns on.
//
// **The BUILD half arrived with CONW-01 and the first line of this header moved
// with it.** It used to say a string goes in and a plain object comes out, which
// stopped being the whole truth the moment `buildContactCard` was added: a
// change goes in and a card comes out too. What did not change is the contract
// that matters — no runtime bindings, no network, no import from the transport,
// and nothing from `src/mail/` in either direction, the same contract
// `./icalendar.ts` keeps beside it, which carries its own read half and write
// half in one file for the same reason. It therefore
// unit-tests against literal fixture strings with nothing stood up, which is
// what lets CONT-02 be asserted under D-09's rule that no automated job may
// authenticate against the real Apple ID.
//
// A real parser rather than a split on line breaks, for the reason
// `src/mail/mime.ts` gives one tree over: folded lines, escaped separators,
// structured values with empty components, and quoted parameters containing
// colons are all the library's problem, and it has met fifteen-year-old real
// address books.
//
// **Every value this module returns is UNTRUSTED CONTENT, and it is returned
// VERBATIM.** A name, organisation, note and address were all typed by
// somebody else, and for a personal assistant reading a real account that means
// anyone whose card ever reached the address book. Framing that text as content
// rather than instruction is the job of `src/mcp/untrusted.ts` at the tool
// boundary, and it is deliberately NOT attempted here (T-03-18): a second
// mitigation of the same threat drifts away from the first, which is what D-56
// rejects. Nothing below trims, escapes, or rewrites a value — the one place
// whitespace is inspected at all is `displayNameFor`, which uses it to DECIDE
// and never to rewrite.
//
// This module contains no logging calls of any kind and must never acquire any.

import ICAL from "ical.js";
import type {
  ContactListEntry,
  NormalizedContactChange,
} from "../confirm";
import { DavConnectError } from "./errors";

/**
 * ical.js is ESM with a DEFAULT EXPORT ONLY — a named import does not resolve.
 * These aliases let the library's types be named without one.
 */
type IcalComponent = InstanceType<typeof ICAL.Component>;
type IcalProperty = InstanceType<typeof ICAL.Property>;

/**
 * The structured name, read positionally.
 *
 * The library hands `N` back as a plain array with the empty string standing
 * for an absent component — no wrapper object, no names. The five fields below
 * are indices 0 through 4 in order, and an empty string becomes null here so a
 * caller never has to know that "" and "absent" meant the same thing.
 */
export interface ContactName {
  /** `N` index 0. */
  family: string | null;
  /** `N` index 1. */
  given: string | null;
  /** `N` index 2. */
  additional: string | null;
  /** `N` index 3. */
  prefix: string | null;
  /** `N` index 4. */
  suffix: string | null;
}

/**
 * The postal address, read positionally.
 *
 * `ADR` is the same shape as `N` and carries the same trap: seven components in
 * a bare array, empty strings for the ones nobody filled in. Indexing past a
 * gap rather than through it shifts every field after it, which is how a
 * postcode ends up reported as a region.
 */
export interface ContactAddress {
  /** `ADR` index 0. */
  poBox: string | null;
  /** `ADR` index 1. */
  extended: string | null;
  /** `ADR` index 2. */
  street: string | null;
  /** `ADR` index 3. */
  locality: string | null;
  /** `ADR` index 4. */
  region: string | null;
  /** `ADR` index 5. */
  postalCode: string | null;
  /** `ADR` index 6. */
  country: string | null;
}

/** One multi-valued property: its value, its types, and its group prefix. */
export interface ContactValue {
  /** Untrusted. Verbatim. Null when the property carries no text value. */
  value: string | null;
  /**
   * The `TYPE` parameters, always as a list.
   *
   * Normalised at the boundary because the accessor returns an array when a
   * property carries several and a bare string when it carries one. Empty when
   * the property names no type at all.
   */
  types: string[];
  /**
   * Apple's `itemN.` group prefix, or null.
   *
   * It is what carries `X-ABLabel` custom labels, and it is exactly the surface
   * a dedicated vCard dependency was feared to be needed for. D-63 removed that
   * dependency on the claim that this library preserves it, and the claim was
   * executed rather than assumed.
   */
  group: string | null;
}

/** One email address on a card. */
export type ContactEmail = ContactValue;

/** One telephone number on a card. */
export type ContactTel = ContactValue;

/** One contact resource, parsed. */
export interface ParsedContact {
  /** The card's unique identifier, as the server stores it. */
  uid: string | null;
  /**
   * `FN`, verbatim — **including when it is present and EMPTY.**
   *
   * The empty string and null are different facts here and both are kept:
   * absent means the card has no such property, empty means iCloud sent one
   * with nothing in it. `displayNameFor` treats them the same way; this field
   * does not, so the distinction survives for anything that needs it.
   */
  formattedName: string | null;
  name: ContactName | null;
  /** `ORG`'s components in order. Empty when the card names no organisation. */
  organisation: string[];
  address: ContactAddress | null;
  /** Untrusted. Verbatim. */
  note: string | null;
  /** Every `EMAIL` property, in document order. */
  emails: ContactEmail[];
  /** Every `TEL` property, in document order. */
  tels: ContactTel[];
}

/**
 * Parse one contact resource body.
 *
 * The design set is chosen automatically from the card's `VERSION` property.
 * iCloud serves 3.0; nothing needs to be told this and nothing should try.
 *
 * Reads every `EMAIL` and every `TEL`, not just the first of each — a real
 * contact has a mobile and a work line, and CONT-02 names both.
 *
 * Throws `DavConnectError` on a body that is not a contact resource: the "came
 * back unusable" branch of that class's own docstring, and a REFUSAL rather
 * than a partial object (T-03-16), because a caller cannot tell a half-built
 * result from a real one. Nothing is read off the caught value.
 */
export function parseVCard(vcfText: string): ParsedContact {
  let card: IcalComponent;
  try {
    card = new ICAL.Component(ICAL.parse(vcfText));
  } catch {
    // Nothing is read from the caught value — not its message, not its stack.
    throw new DavConnectError();
  }
  if (card.name !== "vcard") throw new DavConnectError();

  return {
    uid: textOf(card.getFirstPropertyValue("uid")),
    formattedName: textOf(card.getFirstPropertyValue("fn")),
    name: nameFrom(componentsOf(card.getFirstPropertyValue("n"))),
    organisation: componentsOf(card.getFirstPropertyValue("org")),
    address: addressFrom(componentsOf(card.getFirstPropertyValue("adr"))),
    note: textOf(card.getFirstPropertyValue("note")),
    emails: valuesFrom(card.getAllProperties("email")),
    tels: valuesFrom(card.getAllProperties("tel")),
  };
}

/**
 * The name to show for a contact, with the fallback CONT-01 needs.
 *
 * **This exists because iCloud returns cards with an empty `FN`.** Apple's own
 * developer forums document CardDAV doing exactly that while `N` is populated,
 * inconsistently across resyncs, on contacts that display correctly in the
 * iCloud web app and on an iPhone. A display name read from `FN` alone would
 * therefore show a blank for an unpredictable subset of a real address book —
 * not a hypothetical one, and not a subset anybody can predict or reproduce on
 * demand. That is why this is a fallback rather than defensive decoration.
 *
 * **The second consequence is plan 03-08's, and it is worth stating here
 * because this is where the evidence lives:** a server-side text match on `FN`
 * cannot find those contacts AT ALL. So the client-side search path is not a
 * belt-and-braces duplicate of the server one — it is the only path that can
 * find a person whose card came back this way, which is an independent and
 * concrete argument for it existing.
 *
 * Whitespace is inspected to DECIDE whether a formatted name is blank, and
 * never to rewrite one: a name that is not blank is returned exactly as the
 * card carried it, padding and all. Absent components of `N` are dropped rather
 * than joined through, so a card with only a family name yields that name and
 * not a name with a space in front of it.
 */
export function displayNameFor(contact: ParsedContact): string {
  const formatted = contact.formattedName;
  if (formatted !== null && formatted.trim() !== "") return formatted;
  const name = contact.name;
  if (name === null) return "";
  return [name.given, name.family].filter((part) => part !== null).join(" ");
}

/**
 * Build one contact card from scratch, for a create (CONW-01).
 *
 * ## The library serialises; this file does not
 *
 * Folding at 75 OCTETS, TEXT escaping of `,` `;` and `\`, and CRLF framing are
 * all `Component#toString()`'s job — the same contract `./icalendar.ts` states
 * for the calendar side, and the same reasoning: a hand-rolled writer works on
 * the developer's own test card and corrupts the first real one carrying a
 * comma, and the OCTET half of the fold is the part a character-counting writer
 * gets wrong on the first non-ASCII name. So there is no line breaker here, no
 * escaping, and no character counting.
 *
 * The trailing CRLF is appended because `Component#toString()` emits no
 * terminator after the closing line. The calendar serialiser does the same.
 *
 * ## `REV` and `PRODID` are NOT written, on this path or any later one
 *
 * A value this server invents on every write is a value that makes two
 * serialisations of one change differ — which is exactly the hazard
 * `canonicalChange` records about `DTSTAMP`, and the fidelity proof the update
 * path is built on depends on two serialisations of one change being equal. So
 * nothing is stamped, nothing is versioned, and nothing records that this
 * server was the writer.
 *
 * ## The structured properties take `setValue` and NEVER `setValues`
 *
 * This is the trap worth naming, because both spellings compile and one of them
 * is silently wrong. `N` and `ADR` are declared in the library's vCard design
 * set with BOTH a structured separator (`;`) and a multi-value separator (`,`),
 * and `setValues` writes each element as a separate jCal VALUE — which
 * serialises joined by the multi-value separator. `N:Okonkwo,Adaeze,,,` round
 * trips through this library perfectly and is read by Apple as a single family
 * name whose text happens to contain three commas. `setValue` with the array
 * writes ONE value that IS the array, which serialises as
 * `N:Okonkwo;Adaeze;;;` — the form RFC 6350 defines and the form a real client
 * reads.
 *
 * ## The repeated properties are ADDED, never updated in place
 *
 * One property per list entry through `addProperty`, and never
 * `updatePropertyWithValue`, which PRESERVES the existing property's
 * parameters. A create has no existing property to preserve, so this is
 * discipline for the update path's sake and for the reader's: on that path,
 * updating in place would leave an old `TYPE=` and an old `itemN.` group prefix
 * attached to a new address, which is the grouped-label corruption CONW-03
 * exists to stop. `./icalendar.ts` records the same trap about `DTSTART`.
 */
export function buildContactCard(
  uid: string,
  change: NormalizedContactChange,
): string {
  const card = new ICAL.Component("vcard");
  // 3.0 because that is what iCloud serves and what every fixture in this
  // repository carries. The design set the library applies is chosen from this
  // property, so it is set before anything reads a value type.
  card.updatePropertyWithValue("version", "3.0");
  card.updatePropertyWithValue("uid", uid);

  setOrRemoveText(card, "fn", change.formattedName?.value ?? null);
  setOrRemoveText(card, "note", change.note?.value ?? null);

  if (change.name !== null && change.name !== undefined) {
    const name = change.name;
    setStructured(card, "n", [
      name.family,
      name.given,
      name.additional,
      name.prefix,
      name.suffix,
    ]);
  }

  if (change.address !== null && change.address !== undefined) {
    const address = change.address;
    setStructured(card, "adr", [
      address.poBox,
      address.extended,
      address.street,
      address.locality,
      address.region,
      address.postalCode,
      address.country,
    ]);
  }

  if (change.organisation !== null && change.organisation !== undefined) {
    setStructured(card, "org", change.organisation);
  }

  if (change.emails !== null && change.emails !== undefined) {
    setEntries(card, "email", change.emails);
  }

  if (change.tels !== null && change.tels !== undefined) {
    setEntries(card, "tel", change.tels);
  }

  return `${card.toString()}\r\n`;
}

/**
 * Set a text property to a value, or take it away entirely when it is null.
 *
 * The absent-versus-null rule arrives here already resolved: by the time a
 * change reaches this module, `NormalizedContactChange` has turned "the caller
 * did not mention it" into the OUTER null the caller above checks, so a null
 * reaching this function always means clear it. On a create that is a property
 * never written rather than one removed, and the two are the same card.
 */
function setOrRemoveText(
  card: IcalComponent,
  name: string,
  value: string | null,
): void {
  if (value === null) {
    card.removeAllProperties(name);
    return;
  }
  card.updatePropertyWithValue(name, value);
}

/**
 * Set a structured property from its components, with null read as empty.
 *
 * `setValue` and not `setValues` — see `buildContactCard`'s own docstring, which
 * carries the whole argument. The empty string is what a vCard writes for a
 * component nobody filled in, and `parseVCard` reads it back as null, so the two
 * halves of this file agree about what an absent component looks like on the
 * wire.
 *
 * Removed and re-added rather than updated in place, for the reason
 * `buildContactCard` gives about the repeated properties: the update helper
 * keeps the existing property's parameters, and an `ADR` carries a `TYPE`.
 */
function setStructured(
  card: IcalComponent,
  name: string,
  components: (string | null)[],
): void {
  card.removeAllProperties(name);
  const property = new ICAL.Property(name, card);
  property.setValue(components.map((component) => component ?? ""));
  card.addProperty(property);
}

/**
 * Replace every instance of a repeated property with the supplied list.
 *
 * Whole-list replacement, which is the only contact list edit this project
 * offers: `NormalizedContactChange` carries the argument for why per-entry
 * patching is not on the table. An EMPTY list is a real instruction — remove
 * them all — and reaches here as an empty array rather than as a null, so the
 * removal below is the whole of the work in that case.
 *
 * A `TYPE` parameter is set only when the entry names one. Setting it from an
 * empty list emits `TYPE=:` with nothing after the equals sign, which is a
 * malformed parameter rather than an absent one.
 */
function setEntries(
  card: IcalComponent,
  name: string,
  entries: ContactListEntry[],
): void {
  card.removeAllProperties(name);
  for (const entry of entries) {
    const property = new ICAL.Property(name, card);
    property.setValue(entry.value);
    if (entry.types.length > 0) property.setParameter("type", entry.types);
    card.addProperty(property);
  }
}

/**
 * Structured values, as the plain array the library returns.
 *
 * `N`, `ADR` and `ORG` all come back this way. A single-component value comes
 * back as a bare string instead, which is why that case is lifted into a
 * one-element array here rather than at three call sites.
 */
function componentsOf(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((component) => (typeof component === "string" ? component : ""));
  }
  return typeof value === "string" ? [value] : [];
}

/** `N`'s five components, with the empty string read as absent. */
function nameFrom(components: string[]): ContactName | null {
  if (components.length === 0) return null;
  return {
    family: present(components[0]),
    given: present(components[1]),
    additional: present(components[2]),
    prefix: present(components[3]),
    suffix: present(components[4]),
  };
}

/** `ADR`'s seven components, with the empty string read as absent. */
function addressFrom(components: string[]): ContactAddress | null {
  if (components.length === 0) return null;
  return {
    poBox: present(components[0]),
    extended: present(components[1]),
    street: present(components[2]),
    locality: present(components[3]),
    region: present(components[4]),
    postalCode: present(components[5]),
    country: present(components[6]),
  };
}

/** Every value of a repeated property, with its types and its group. */
function valuesFrom(properties: IcalProperty[]): ContactValue[] {
  return properties.map((property) => ({
    value: textOf(property.getFirstValue()),
    types: normaliseTypes(property.getParameter("type")),
    group: firstParameter(property, "group"),
  }));
}

/**
 * The `TYPE` parameters as a list, whatever shape the accessor returned.
 *
 * **One place, so there is one place it can be got right.** The accessor
 * returns an ARRAY when a property carries several `TYPE` parameters and a
 * BARE STRING when it carries one, and mapping over the string yields its
 * characters — `"CELL"` becomes `["C", "E", "L", "L"]`, which is silently
 * wrong rather than an error and would sail through any test whose fixture
 * happened to use two types.
 */
function normaliseTypes(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === "string");
  }
  return typeof value === "string" ? [value] : [];
}

/** One parameter value, normalised the same way and narrowed to one. */
function firstParameter(property: IcalProperty, name: string): string | null {
  return normaliseTypes(property.getParameter(name))[0] ?? null;
}

/** A structured component, with the empty string read as absent. */
function present(component: string | undefined): string | null {
  return component === undefined || component === "" ? null : component;
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
