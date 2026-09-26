// The contact WRITE boundary: preview, mint, commit (CONW-01).
//
// The confirm gate's first new consumer since Phase 15 built it, and this module
// deliberately invents nothing. `./calendar.ts` is copied end to end — the fence
// split, the mint, the single composer, `applyCommit`'s fixed order — because a
// second shape for the same guarantee is two shapes that agree only until
// somebody edits one of them.
//
// **Its own file rather than more registrations inside `./contacts.ts`, and the
// reason is what the two files each hold.** That one is read-side: two tools, two
// shapers, and a trusted half that is three fields wide. This one holds a change
// vocabulary, a normaliser, a mint, a commit with a seven-step refusal order and
// two more shapers. Putting them together would make the read tools' response
// shaping the smaller half of a file about writing. The REGISTRATION still runs
// through `registerContactsTools`, and that is not an oversight either: the
// per-tool description ceiling in `test/dav-tools.test.ts` reaches the contacts
// surface through that one registrar, so a registration added behind it is
// measured by construction rather than by somebody remembering to extend a
// harness.
//
// The import of `CONTACTS_UNTRUSTED_NOTICE` from `./contacts` closes a cycle
// with that file's own import of `registerContactsWriteTools`. It is safe
// because every use of the notice is inside a function body rather than at
// module scope: the value is read when a registrar runs, long after both modules
// have finished evaluating. A description assembled into a module-level constant
// here would be a temporal-dead-zone error at import time rather than a test
// failure, so keep them where they are.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { z } from "zod";
import {
  CONFIRM_TTL_SECONDS,
  CONFIRM_VERSION,
  ConfirmationInvalidError,
  changeHashMatches,
  composeConfirmationLine,
  contactChangeHashOf,
  mintConfirmation,
  reserveConfirmation,
  verifyConfirmation,
} from "../../confirm";
import type {
  ContactAddressEdit,
  ContactListEntry,
  ContactNameEdit,
  ContactTextEdit,
  NormalizedContactChange,
} from "../../confirm";
import {
  contactUidFromObjectUrl,
  createContact,
  findDuplicateCandidates,
  getContactWithEtag,
  planContactCreateTarget,
  updateContact,
} from "../../dav/contacts";
import type { DuplicateCandidate } from "../../dav/contacts";
import { DavConfirmationError, DavStaleResourceError } from "../../dav/errors";
import { decodeContactId, encodeContactId } from "../../dav/ids";
import type { ContactRef } from "../../dav/ids";
import type { DavFetch } from "../../dav/transport";
import {
  buildContactCard,
  countPreservedProperties,
  displayNameFor,
  patchContactCard,
} from "../../dav/vcard";
import type { ParsedContact } from "../../dav/vcard";
import type { ToolResult } from "../untrusted";
import { untrustedToolResult } from "../untrusted";
import { CONTACTS_UNTRUSTED_NOTICE } from "./contacts";
import { davErrorResult } from "./dav-diagnose";
import type { Principal } from "../../principal";

/**
 * The field names a contact write may report, as a CLOSED vocabulary.
 *
 * `CHANGE_FIELDS`' twin one module over, and closed for that constant's own
 * reason: a field name a caller could choose is not a name, it is content — and
 * this list travels in the TRUSTED half of both responses. The VALUES these
 * names refer to are in the other half.
 *
 * Fixed order, so two responses about the same change list the same fields in
 * the same sequence and a reader can compare them by eye.
 */
const CONTACT_CHANGE_FIELDS = [
  "formattedName",
  "name",
  "organisation",
  "address",
  "note",
  "emails",
  "tels",
] as const satisfies readonly (keyof NormalizedContactChange)[];

/** One field of a contact change, named. */
export type ContactChangeField = (typeof CONTACT_CHANGE_FIELDS)[number];

/**
 * What one contact create supplies on the wire.
 *
 * **Every optional field is `?: T | null` and the two spellings mean different
 * things**, which is the whole of CONW-03's guarantee expressed at the boundary:
 * omitting the key leaves whatever the card holds, and passing `null` clears it.
 * `normalizeSuppliedContact` is the single place they are told apart.
 */
export interface SuppliedContactChange {
  kind: "create" | "update";
  formattedName?: string | null;
  name?: {
    family?: string | null;
    given?: string | null;
    additional?: string | null;
    prefix?: string | null;
    suffix?: string | null;
  } | null;
  organisation?: string[] | null;
  address?: {
    poBox?: string | null;
    extended?: string | null;
    street?: string | null;
    locality?: string | null;
    region?: string | null;
    postalCode?: string | null;
    country?: string | null;
  } | null;
  note?: string | null;
  emails?: { value: string; types?: string[] }[] | null;
  tels?: { value: string; types?: string[] }[] | null;
}

/**
 * What a contact write preview answers with. Nothing has been written.
 *
 * ONE type for both operations rather than two, and `willCreate` is what tells
 * them apart. Two independently declared shapes would agree today and drift the
 * first time either grew a field — silently, because both would still serialise
 * into a plausible response — which is the argument `ContactDetail` records for
 * extending `ContactSummary` rather than paralleling it. Here it is sharper
 * still: the fence audit walks this shape's key set, so a second shape would be
 * a second thing the fence has to be taught about.
 *
 * It was called `ContactCreatePreview` until the update arrived, and the rename
 * is not tidying: a type named for one operation is a type the next reader
 * copies for the other.
 */
export interface ContactWritePreview {
  /**
   * The opaque contact id.
   *
   * On a create, the card the preview PLANNED, minted before anything exists. On
   * an update, the card that was fetched — byte-identical to the id the caller
   * supplied, because an update moves nothing.
   */
  id: string;
  /**
   * Which operation was previewed: true brings a new card into being, false
   * overwrites one that already exists.
   *
   * **It discriminates now, and it was constantly true before the update
   * existed.** A boolean nobody could read a `false` out of is a field that
   * teaches a reader to skip it, so the one fact worth checking about the two
   * legs would have been the field nobody looked at.
   */
  willCreate: boolean;
  /** Field NAMES from `CONTACT_CHANGE_FIELDS`. Never values. */
  changedFields: ContactChangeField[];
  /** How many of them. */
  fieldCount: number;
  /** The capability that authorises the commit. */
  confirmToken: string;
  /** Its remaining life, in whole seconds. */
  expiresInSeconds: number;
  /** The normalized change, echoed so the commit can pass it back unaltered. */
  change: NormalizedContactChange;
  /** The sentence this server wrote for a person to read. */
  confirmationLine: string;
  /**
   * How many existing cards already carry one of the supplied values (CONW-05).
   *
   * **Present on EVERY preview, zero included**, so the key set does not vary
   * between one preview and the next. A field that appears only when it is
   * interesting teaches a reader to treat its absence as the absence of the
   * question rather than as an answer to it.
   */
  duplicateCandidateCount: number;
  /**
   * The candidates themselves, at most three (CONW-05).
   *
   * **An observation this server made at preview time, like an ETag — NOT part
   * of the signed change.** It never enters `canonicalContactChange` or the
   * hash, deliberately: binding it would make the commit refuse a write because
   * somebody else added a card in between, which is not what CONW-06 is for and
   * not a refusal anybody asked for (T-16-19).
   *
   * Nothing has been merged, nothing redirected and nothing refused. Committing
   * creates a new card ALONGSIDE these.
   */
  duplicateCandidates: DuplicateCandidate[];
  /**
   * How many properties on the existing card this change leaves alone (CONW-02).
   *
   * **PITFALLS #40's own recommendation, made concrete.** A CardDAV update is a
   * whole-card overwrite, so the user's real question is not "what changes" but
   * "what survives" — and a preview showing only the new value is one of the
   * warning signs Pitfall 39 lists for exactly this operation. "Changing 1
   * field, 23 other properties preserved" is a sentence somebody can check
   * against the card in front of them.
   *
   * A COUNT this server took by walking the card it fetched, never a value read
   * off that card, which is why it rides outside the fence beside
   * `duplicateCandidateCount`.
   *
   * **Present on EVERY preview, and ZERO on a create**, so the key set does not
   * vary between one preview and the next — `duplicateCandidateCount`'s own
   * argument. Zero is the true answer for a create rather than a placeholder:
   * there is no existing card, so there is nothing being preserved.
   */
  preservedPropertyCount: number;
}

/** What a finished contact commit answers with. */
export interface ContactCommitOutcome {
  applied: boolean;
  id: string;
  changedFields: ContactChangeField[];
  fieldCount: number;
  change: NormalizedContactChange;
  /** The same sentence, restated in the past tense by the same composer. */
  confirmationLine: string;
}

/**
 * The half of a preview this server planned, counted or minted.
 *
 * Nine fields, and every one of them is a statement about this server's own
 * work: an opaque id it minted from a target it planned or was handed, a boolean
 * it decided, a list of names from its OWN closed vocabulary, that list's
 * length, the capability it signed, that capability's life, a COUNT of cards it
 * found, a row per candidate carrying two opaque ids and a label from a closed
 * three-value vocabulary it chose from, and a COUNT of properties it took by
 * walking the card it fetched.
 *
 * **Note what is NOT here: `confirmationLine`.** It quotes a card-supplied name,
 * so it rides in the untrusted half — Phase 15 decided that and this module is
 * the first new consumer to inherit it rather than the first to reopen it.
 *
 * **And note what is not here from the candidates: every word off the cards.** A
 * candidate's display name and its addresses came off a card somebody else wrote,
 * and an address is the field a reader is most likely to assume is safe because
 * it looks like a protocol value. The COUNT and the SIGNAL are this server's, on
 * `matchPath`'s own precedent one module over.
 */
function contactPreviewTrustedPart(
  preview: ContactWritePreview,
): Record<string, unknown> {
  return {
    id: preview.id,
    willCreate: preview.willCreate,
    changedFields: preview.changedFields,
    fieldCount: preview.fieldCount,
    confirmToken: preview.confirmToken,
    expiresInSeconds: preview.expiresInSeconds,
    duplicateCandidateCount: preview.duplicateCandidateCount,
    duplicateCandidates: preview.duplicateCandidates.map((one) => ({
      id: one.id,
      addressBookId: one.addressBookId,
      signal: one.signal,
    })),
    preservedPropertyCount: preview.preservedPropertyCount,
  };
}

/**
 * The half somebody typed: the change itself, and the sentence quoting it.
 *
 * A contact's split is as lopsided as `contactToolResult`'s and for the same
 * reason — a card is a bag of text somebody chose, so a change to one is a bag
 * of text a caller chose. The name, the organisation, the note, the postal
 * address and every address and number are all in here.
 */
function contactPreviewUntrustedPart(
  preview: ContactWritePreview,
): Record<string, unknown> {
  return {
    // Repeated from the trusted half so the model joins the two BY IDENTITY.
    id: preview.id,
    change: preview.change,
    // The sentence this server wrote for a person to read. It quotes the card's
    // own name, so it belongs on this side. The fence did not move to
    // accommodate it and must not.
    confirmationLine: preview.confirmationLine,
    // Every word somebody ELSE wrote onto the cards this scan found. The rows are
    // keyed on the same container name as the trusted half and repeat the opaque
    // id, so the model joins the two halves BY IDENTITY exactly as it does for the
    // preview itself.
    duplicateCandidates: preview.duplicateCandidates.map((one) => ({
      id: one.id,
      displayName: one.displayName,
      emails: one.emails,
    })),
  };
}

/**
 * Shape a contact create preview into the tool's response.
 *
 * Exported for the reason every shaper in this tree is: the fence assertions
 * over this shape are a WALK and a key-set comparison, and either run against a
 * test-local copy would prove something about the copy.
 */
export function contactPreviewToolResult(
  preview: ContactWritePreview,
): ToolResult {
  return untrustedToolResult(
    contactPreviewTrustedPart(preview),
    contactPreviewUntrustedPart(preview),
  );
}

/** The half of a commit this server did, counted or decided. */
function contactCommitTrustedPart(
  outcome: ContactCommitOutcome,
): Record<string, unknown> {
  return {
    applied: outcome.applied,
    id: outcome.id,
    changedFields: outcome.changedFields,
    fieldCount: outcome.fieldCount,
  };
}

/** The half somebody typed, echoed back as data. */
function contactCommitUntrustedPart(
  outcome: ContactCommitOutcome,
): Record<string, unknown> {
  return {
    id: outcome.id,
    change: outcome.change,
    confirmationLine: outcome.confirmationLine,
  };
}

/** Shape a finished contact commit into the tool's response. */
export function contactCommitToolResult(
  outcome: ContactCommitOutcome,
): ToolResult {
  return untrustedToolResult(
    contactCommitTrustedPart(outcome),
    contactCommitUntrustedPart(outcome),
  );
}

/**
 * Run something that may raise the NEUTRAL confirmation refusal, and translate.
 *
 * A LOCAL twin of `withConfirmationBoundary` in `./calendar.ts`, which that
 * module does not export. Exporting it to reach it here was the alternative and
 * was declined: that module carries a DAV write manifest of its own, and
 * widening its exported surface for a six-line try/catch costs more than the
 * twin does. The original is named so the two can be compared.
 *
 * `src/confirm.ts` is protocol-neutral and raises `ConfirmationInvalidError`;
 * `davToErrorCategory` dispatches on TYPE and falls through to a connection
 * diagnosis for anything it does not recognise, so a neutral error that escaped
 * untranslated would tell the caller the network failed when what actually
 * happened is that a confirmation was refused. That points at the wrong remedy:
 * it tells a model to retry the thing that will be refused identically forever.
 *
 * Wrapped around BOTH legs rather than only the commit, because minting raises
 * the same class when the signing key is unusable — and a preview reporting
 * `connection_failed` for an unprovisioned secret would send the user looking at
 * their network.
 *
 * Nothing is read off the caught value. The rethrown class takes no constructor
 * argument, so there is nowhere for a cause to ride even by accident.
 */
async function withContactConfirmationBoundary<T>(
  run: () => Promise<T>,
): Promise<T> {
  try {
    return await run();
  } catch (err) {
    if (err instanceof ConfirmationInvalidError) {
      throw new DavConfirmationError();
    }
    throw err;
  }
}

/**
 * Resolve the wire shape into the normalized change, absent apart from cleared.
 *
 * **This is the ONE place in the project where "the caller did not mention it"
 * and "the caller asked for it to be cleared" are told apart, and the code says
 * so out loud rather than leaving it to a reader to spot.** Every branch below
 * is the same two-line shape: `undefined` becomes the outer `null`, and an
 * explicit `null` becomes the cleared form for that field's kind.
 *
 * Once past this function the distinction is carried by the TYPE, and
 * `canonicalContactChange` turns it into different bytes, so no call site
 * downstream re-derives it. That is deliberate: a distinction re-derived at two
 * sites is one that eventually disagrees with itself, and the disagreement would
 * be a confirm-gate bypass rather than a bug in a listing.
 *
 * A wire `null` for a LIST becomes the empty array rather than the outer null,
 * because "clear the list" and "replace the list with nothing" are the same
 * instruction and the empty array is the form that says it. Two wire spellings
 * therefore land on one normalized value, which is safe for the hash: the hash
 * is taken over the NORMALIZED change at both legs, so the preview and the
 * commit agree whichever spelling each used.
 */
function normalizeSuppliedContact(
  supplied: SuppliedContactChange,
): NormalizedContactChange {
  return {
    kind: supplied.kind,
    formattedName: textEdit(supplied.formattedName),
    name:
      supplied.name === undefined
        ? null
        : nameEdit(supplied.name),
    organisation:
      supplied.organisation === undefined
        ? null
        : (supplied.organisation ?? []),
    address:
      supplied.address === undefined
        ? null
        : addressEdit(supplied.address),
    note: textEdit(supplied.note),
    emails: listEdit(supplied.emails),
    tels: listEdit(supplied.tels),
  };
}

/** A text field: absent stays absent, and anything else becomes the wrapper. */
function textEdit(value: string | null | undefined): ContactTextEdit | null {
  return value === undefined ? null : { value };
}

/** `N`, whole. A wire null clears the property, so every component is null. */
function nameEdit(
  supplied: SuppliedContactChange["name"],
): ContactNameEdit {
  return {
    family: supplied?.family ?? null,
    given: supplied?.given ?? null,
    additional: supplied?.additional ?? null,
    prefix: supplied?.prefix ?? null,
    suffix: supplied?.suffix ?? null,
  };
}

/** `ADR`, whole. Same rule, over its own seven components. */
function addressEdit(
  supplied: SuppliedContactChange["address"],
): ContactAddressEdit {
  return {
    poBox: supplied?.poBox ?? null,
    extended: supplied?.extended ?? null,
    street: supplied?.street ?? null,
    locality: supplied?.locality ?? null,
    region: supplied?.region ?? null,
    postalCode: supplied?.postalCode ?? null,
    country: supplied?.country ?? null,
  };
}

/**
 * A repeated property's whole list.
 *
 * `types` defaults to the empty list rather than to a guess. A card that names
 * no type is a real card, and inventing `INTERNET` or `VOICE` here would be this
 * server writing a label nobody asked for onto somebody's contact.
 */
function listEdit(
  supplied: { value: string; types?: string[] }[] | null | undefined,
): ContactListEntry[] | null {
  if (supplied === undefined) return null;
  return (supplied ?? []).map((entry) => ({
    value: entry.value,
    types: entry.types ?? [],
  }));
}

/**
 * Which fields a change MENTIONS, by name, in `CONTACT_CHANGE_FIELDS` order.
 *
 * Names and never values, because this list travels in the trusted half. A field
 * counts as mentioned when its slot is not the outer `null` — so clearing a field
 * is a change to it, which is the answer the user needs: a preview that reported
 * nothing changing while a note was about to be deleted would be under-warning
 * on exactly the direction this project must never fail in.
 */
function changedContactFields(
  change: NormalizedContactChange,
): ContactChangeField[] {
  return CONTACT_CHANGE_FIELDS.filter((field) => change[field] !== null);
}

/**
 * The name to put in the sentence, read off the change AS IT WILL BE WRITTEN.
 *
 * Through `displayNameFor` rather than off the supplied `FN` directly, and this
 * is not defensive decoration: **iCloud returns cards with an empty `FN` while
 * `N` is populated**, Apple's own forums document it, and `displayNameFor`'s
 * docstring carries the evidence. A caller mirroring a card it read would supply
 * exactly that pair, and a line naming `''` would be this server reporting a
 * contact as nameless while writing one with a name.
 *
 * A projection into `ParsedContact` rather than a second name-folding rule, so
 * the write path and the read path answer "what is this card called" with one
 * function. Only the two fields `displayNameFor` reads are populated; the rest
 * are the empty values the type requires and nothing looks at them.
 */
function displayNameForChange(change: NormalizedContactChange): string {
  const projection: ParsedContact = {
    uid: null,
    formattedName: change.formattedName?.value ?? null,
    name:
      change.name === null
        ? null
        : {
            family: change.name.family,
            given: change.name.given,
            additional: change.name.additional,
            prefix: change.name.prefix,
            suffix: change.name.suffix,
          },
    organisation: [],
    address: null,
    note: null,
    emails: [],
    tels: [],
  };
  return displayNameFor(projection);
}

/**
 * The FIRST value on a supplied list, or null for a list with nothing on it.
 *
 * First and not every one, because a create carrying five addresses must not cost
 * five queries — the phase's locked "at most two queries" decision is about the
 * whole scan and not about one field. The first is the one the caller led with,
 * and both routes probe the same two values, so the two stay in agreement with
 * each other rather than each seeing a different slice of the change.
 *
 * A blank value is null rather than a probe. `findDuplicateCandidates` would
 * match nothing on it, but supplying it would still spend a query.
 */
function firstProbeValue(entries: ContactListEntry[] | null): string | null {
  if (entries === null) return null;
  for (const entry of entries) {
    if (entry.value.length > 0) return entry.value;
  }
  return null;
}

/**
 * Preview a contact create: plan a target, scan for duplicates, write nothing.
 *
 * ## What reaches the network, and what does not
 *
 * The create itself reaches nothing: its target is computed from an opaque id and
 * its confirmation is signed locally, so that half is a decode, a uuid, a hash and
 * an HMAC. The duplicate scan (CONW-05) is the only outbound cost on this leg, and
 * it is bounded rather than incidental — at most two filtered queries, issued
 * serially, and **NOTHING AT ALL when the change carries neither an address nor a
 * telephone number.** See `findDuplicateCandidates` for the whole cost argument.
 *
 * ## The order, and why the scan sits where it does
 *
 * Whether the scan runs inside this builder or beside it is the phase context's
 * explicit discretion. It runs inside, AFTER the target has been planned and
 * BEFORE the confirmation is minted, for two reasons: a refusal that costs nothing
 * still costs nothing, because planning is free and comes first; and the candidate
 * list becomes a fact about the moment the user was shown rather than about some
 * later moment.
 *
 * ## The candidates change nothing
 *
 * They are not in the signed change and never enter the hash — see the field's own
 * docstring. Nothing is merged, nothing is copied off a candidate, the write is not
 * redirected to one, and no write is refused because one exists. Refusing would
 * make a legitimate second card for the same person impossible to create, which is
 * why CONW-05 asks for surfacing rather than for a gate.
 *
 * ## The target is planned before anything exists
 *
 * `planContactCreateTarget` mints the uid and the object url now, so the
 * confirmation binds the card this preview is describing. See its own docstring
 * for why that also gives a create the second replay defence the update kind
 * gets from `If-Match`.
 *
 * ## A change that names nothing is refused
 *
 * `buildContactUpdatePreview` carries the general reason: a confirmation for a
 * no-op is a capability nobody should be holding. The create leg has a sharper
 * one of its own. A no-op update writes a card identical to the one fetched, but
 * a no-op CREATE writes a card whose entire content is a version and a uid — no
 * `FN` and no `N`, both of which vCard 3.0 requires (RFC 2426 sections 3.1.1 and
 * 3.1.2). Either iCloud accepts it, and the user has an unnamed empty card on
 * the account and on every device; or iCloud refuses it, and the refusal lands
 * after `reserveConfirmation` has spent the one-time slot, so the caller cannot
 * retry the corrected request with the confirmation they were handed. The
 * confirmation line would also name nothing — `displayNameForChange` answers
 * the empty string for a change carrying no name at all, so the sentence the
 * user must be shown before a write would read `Creating contact ''.`
 *
 * Refused ahead of the scan, so it costs no outbound request either.
 */
async function buildContactCreatePreview(
  principal: Principal,
  davFetch: DavFetch,
  addressBookId: string,
  supplied: SuppliedContactChange,
): Promise<ContactWritePreview> {
  const ref = planContactCreateTarget(addressBookId);
  const change = normalizeSuppliedContact(supplied);
  const fields = changedContactFields(change);

  // BEFORE the scan, so a no-op create costs zero outbound requests as well as
  // being refused. `buildContactUpdatePreview`'s own reason applies here — a
  // confirmation for a no-op is a capability nobody should be holding — and it
  // is SHARPER on this leg, because a create is the one that would go through:
  // the card `buildContactCard` would write carries neither `FN` nor `N`, both
  // mandatory in vCard 3.0, so iCloud either accepts an unnamed empty card onto
  // the account and every device the user owns, or refuses it AFTER
  // `reserveConfirmation` has already spent the one-time slot, leaving the
  // caller unable to retry with the confirmation they hold.
  if (fields.length === 0) throw new ConfirmationInvalidError();

  const id = encodeContactId(ref);

  const duplicateCandidates = await findDuplicateCandidates(
    env,
    principal,
    davFetch,
    {
      email: firstProbeValue(change.emails),
      tel: firstProbeValue(change.tels),
      // RANKS and never queries. Through `displayNameForChange` so the name the
      // scan compares is the name the card will actually be called — including
      // the empty-`FN` fallback that function exists for.
      displayName: displayNameForChange(change),
      // NULL: a create has no card yet, so there is nothing to exclude. The
      // update kind passes the card it is updating.
      excludeObjectUrl: null,
    },
  );

  const confirmToken = await mintConfirmation(
    {
      v: CONFIRM_VERSION,
      // The kind of resource this confirmation names, placed immediately after
      // the version so the discriminator reads before the fields it governs.
      t: "dav",
      k: "create",
      j: crypto.randomUUID(),
      c: ref.addressBookUrl,
      o: ref.objectUrl,
      // NULL: a card has no recurrence, so there is nothing for this field to
      // discriminate. Present and null rather than absent, because the arm's
      // type says the field is there.
      r: null,
      // NULL, and `ConfirmPayload.e`'s own docstring names this as the one case
      // for it: a create has no ETag to bind, because there is nothing there
      // yet. The commit ENFORCES it rather than assuming it.
      e: null,
      // NULL: a vCard has no `SEQUENCE`. Unlike the calendar's create, where
      // null means "no resource yet", here it means the concept does not exist
      // on this protocol at all — and `createContact` never reads it.
      s: null,
      // The fields this preview named, sealed — **and the contact commit does NOT
      // read it back, on `ConfirmPayload.s`'s own precedent.** It cannot drift:
      // `changedContactFields` reads nothing but the change, and the hash binds
      // the change, so both legs call one function over one bound value and
      // arrive at the same list by construction. That is the property the
      // calendar's update leg does not have, which is why `f` exists at all. The
      // fact is true of this preview either way and it costs a list already in
      // hand; a null or an omission here would be this leg claiming the preview
      // named nothing.
      f: fields,
      h: await contactChangeHashOf(change),
      x: Math.floor(Date.now() / 1000) + CONFIRM_TTL_SECONDS,
      // NOT null, unlike the three fields above it. A contact create has no
      // ETag, no recurrence and no revision, but it has a user: the one who
      // asked for it, from the signed-in principal.
      u: principal.userId,
    },
    env.CONFIRM_SECRET,
  );

  return {
    id,
    willCreate: true,
    changedFields: fields,
    fieldCount: fields.length,
    confirmToken,
    expiresInSeconds: CONFIRM_TTL_SECONDS,
    change,
    confirmationLine: composeConfirmationLine(
      {
        kind: "create",
        noun: "contact",
        name: displayNameForChange(change),
        // A create brings one card into being and takes nothing with it.
        alsoRemoved: null,
        // **NULL and deliberately not the field count**, which is published as
        // its own trusted number one block up. Every field on a create is new,
        // so "changing 3 fields" would be counting the card rather than
        // describing a change — `buildCreatePreview` in `./calendar.ts` made the
        // same call for the same reason, and 16-PATTERNS records the resulting
        // line as `Creating contact 'Jane Doe'. Undoing it is a separate,
        // explicit request.`
        fieldCount: null,
        // NULL and NOT zero. `composeConfirmationLine` switches its whole
        // consequence clause on this field, and a contact write invites nobody:
        // no invitation leaves the building on this path, so the clause the user
        // must read is the one about undoing it.
        recipientCount: null,
        // NULL. A contact has no reminders. Present and null rather than
        // absent, on `ConfirmationSummary`'s own rule: an operation that cannot
        // touch one says so, and a field that can be ABSENT is a field a later
        // build reads as `undefined`.
        alarms: null,
        reply: null,
      },
      "would",
    ),
    duplicateCandidateCount: duplicateCandidates.length,
    duplicateCandidates,
    // ZERO, and the true answer rather than a placeholder: there is no existing
    // card, so there is nothing being preserved. Present because the key set
    // must not vary between one preview and the next — see the field's own
    // docstring.
    preservedPropertyCount: 0,
  };
}

/**
 * Preview a contact update: read the card, count what survives, write nothing.
 *
 * ## What reaches the network, and in what order
 *
 * TWO reads at most, both on the preview leg and both serial. The card itself,
 * through `getContactWithEtag` — one request, and the entity tag it brings back is
 * what the confirmation binds. Then the duplicate scan (CONW-05), which costs
 * nothing at all when the change carries neither an address nor a number.
 *
 * The id is decoded FIRST, before anything reaches the network, because that is
 * the cheapest possible refusal of a forged id and the kind letter inside the
 * token is what stops a calendar id resolving here into a plausible-looking
 * contact reference.
 *
 * ## The scan excludes the card being updated
 *
 * `excludeObjectUrl` is this card's own object url, so an update never offers the
 * card it is updating as its own duplicate. That is CONW-05 on the update side
 * and it is the reason that parameter exists — a card matched against its own
 * address would otherwise be presented as a second person with the same details,
 * which is the one candidate that is certainly not one.
 *
 * ## `preservedPropertyCount` is the field this preview exists for
 *
 * A CardDAV update is a whole-card overwrite, so the question the user actually
 * has is what survives. See the field's own docstring for the whole argument; the
 * mechanism is a walk over the FETCHED card's own properties in
 * `countPreservedProperties`, which is why it can count a property this project
 * has never heard of.
 *
 * ## A change that names nothing is refused
 *
 * There is no write to confirm, and a confirmation for a no-op is a capability
 * nobody should be holding. Refused BEFORE the read, so it costs nothing.
 */
async function buildContactUpdatePreview(
  principal: Principal,
  davFetch: DavFetch,
  contactId: string,
  supplied: SuppliedContactChange,
): Promise<ContactWritePreview> {
  // BEFORE the network. A forged id is refused having sent nothing.
  const ref = decodeContactId(contactId);
  const change = normalizeSuppliedContact(supplied);
  const fields = changedContactFields(change);

  // Also before the network. See the docstring: a confirmation for a no-op is a
  // capability nobody should be holding, and refusing it here costs nothing.
  if (fields.length === 0) throw new ConfirmationInvalidError();

  const fetched = await getContactWithEtag(env, principal, davFetch, ref);

  // The NAME the user reads, and it comes off the FETCHED card. `detail`'s
  // `displayName` IS `displayNameFor`'s output over the bytes just fetched, which
  // is what carries the empty-`FN` fallback: iCloud returns cards with an empty
  // `FN` while `N` is populated, inconsistently across resyncs, on contacts that
  // display correctly everywhere else — that function's docstring holds the
  // evidence. A write path reading `FN` directly reports a named contact as
  // nameless on a real subset of the owner's address book, and this is the
  // sentence somebody reads before agreeing to an overwrite.
  const name = fetched.detail.displayName;

  // SERIAL, after the read and before the mint. Two awaits and never a pair:
  // `getContactWithEtag` and `findDuplicateCandidates` are both named in the
  // `dav-concurrent-request` alternation, and so is this function.
  const duplicateCandidates = await findDuplicateCandidates(
    env,
    principal,
    davFetch,
    {
      email: firstProbeValue(change.emails),
      tel: firstProbeValue(change.tels),
      // RANKS and never queries, exactly as on the create — and off the FETCHED
      // card rather than off the change, because the change may not mention a
      // name at all.
      displayName: name,
      // THIS card. An update must not offer the card it is updating as its own
      // duplicate, which is why this parameter exists at all.
      excludeObjectUrl: ref.objectUrl,
    },
  );

  const confirmToken = await mintConfirmation(
    {
      v: CONFIRM_VERSION,
      t: "dav",
      k: "update",
      j: crypto.randomUUID(),
      c: ref.addressBookUrl,
      o: ref.objectUrl,
      // NULL: a card has no recurrence, so there is nothing to discriminate.
      r: null,
      // **NOT null, and this is the distinction the create arm's refusal makes
      // load-bearing.** `ConfirmPayload.e` is null ONLY for a create; an update
      // binds the version stamp observed one read ago, and the commit sends it
      // back as the conditional header. Byte-exact, quotes included — a
      // re-quoted value is a different version as far as the server is
      // concerned.
      e: fetched.etag,
      // NULL: a vCard has no `SEQUENCE`. The concept does not exist on this
      // protocol, and `updateContact` never reads it.
      s: null,
      // Sealed and not read back, for the create leg's stated reason. **And the
      // contrast with the calendar's update leg is worth naming here, because
      // this is the leg that looks most like it.** A contact change distinguishes
      // "not mentioned" from "clear this" in the TYPE — `ContactTextEdit`'s outer
      // null — so the confirmed change still says which fields the caller spoke
      // about, and `changedContactFields` reads exactly that. A calendar update
      // resolves an unmentioned field to the stored value instead, which is what
      // erased the distinction there and produced eight where one moved.
      f: fields,
      h: await contactChangeHashOf(change),
      x: Math.floor(Date.now() / 1000) + CONFIRM_TTL_SECONDS,
      u: principal.userId,
    },
    env.CONFIRM_SECRET,
  );

  return {
    id: encodeContactId(ref),
    // FALSE. The field discriminates the two previews rather than being
    // constantly true, which is what makes it worth a reader's attention.
    willCreate: false,
    changedFields: fields,
    fieldCount: fields.length,
    confirmToken,
    expiresInSeconds: CONFIRM_TTL_SECONDS,
    change,
    confirmationLine: composeConfirmationLine(
      {
        kind: "update",
        noun: "contact",
        name,
        // An overwrite takes nothing else with it: a card is not a container.
        alsoRemoved: null,
        // **The field count, unlike the create's null.** On a create every field
        // is new, so "changing 3 fields" would be counting the card rather than
        // describing a change. On an update it is the whole point — it is the
        // number that says how much of an existing card is being replaced.
        fieldCount: fields.length,
        // NULL and NOT zero. The composer switches its whole consequence clause
        // on this field, and a contact write invites nobody: no invitation
        // leaves the building on this path, so the clause the user must read is
        // the one saying the previous values cannot be recovered.
        recipientCount: null,
        // NULL. A contact has no reminders. Present and null rather than
        // absent, on `ConfirmationSummary`'s own rule: an operation that cannot
        // touch one says so, and a field that can be ABSENT is a field a later
        // build reads as `undefined`.
        alarms: null,
        reply: null,
      },
      "would",
    ),
    duplicateCandidateCount: duplicateCandidates.length,
    duplicateCandidates,
    preservedPropertyCount: countPreservedProperties(fetched.body, change),
  };
}

/**
 * Apply a previewed contact write, or refuse having spent nothing.
 *
 * ## The order, and why every step is where it is
 *
 *   1-3b. Verify the signature, the version, the expiry, the user and the target.
 *   4.    The operation comes from the SIGNED payload.
 *   4b.   The SUPPLIED change's kind agrees with the SIGNED one.
 *   5.    Recompute the change hash and compare it constant-time.
 *   6.    Claim the one-time slot.
 *   7.    Only now: read the target from the payload and write.
 *
 * The create arm's step 7 is one request. The update arm's is four steps and TWO
 * requests — re-read, compare the version locally, patch the bytes just read,
 * write conditionally on the SIGNED version — and each of those is argued at its
 * own line. Two serial awaits and never a pair: the fan-out rule bans concurrency
 * and not request count, and its own text permits this shape by name.
 *
 * Copied from `applyCommit` in `./calendar.ts` including the numbering, so the
 * two can be read side by side and a step missing from one is visible.
 *
 * Every refusal above returns the same category and the same fixed message.
 * Nothing names the check that failed, quotes the token back, or mentions a
 * field, a version or an encoding. A distinguishable refusal turns this endpoint
 * into an oracle for the confirmation's internal structure, and the commonest
 * way to reach one is a model probing the format.
 *
 * **Nothing before step 6 spends an outbound request**, which is the property
 * the reservation exists for and the one `If-Match` structurally cannot deliver,
 * because `If-Match` IS the request it would have to precede.
 */
async function applyContactCommit(
  principal: Principal,
  davFetch: DavFetch,
  confirmToken: string,
  supplied: SuppliedContactChange,
): Promise<ContactCommitOutcome> {
  // Steps 1, 2, 3, 3a and 3b.
  //
  // The target is supplied here and checked THERE. Nothing below compares
  // `payload.t` again: the gate owns that check, the payload it returns is
  // already narrowed to the object arm, and a second comparison at this call
  // site is the duplicate a later phase copies to a call site that then forgets
  // it.
  const payload = await verifyConfirmation(
    confirmToken,
    env.CONFIRM_SECRET,
    principal.userId,
    "dav",
  );

  // Step 4. Read from the SIGNED payload, never inferred from which tool was
  // called. A contact DELETE is out of scope for this phase by the roadmap's own
  // decision, so a `delete` payload presented here is refused rather than
  // falling through to an arm nobody wrote.
  if (payload.k !== "create" && payload.k !== "update") {
    throw new ConfirmationInvalidError();
  }

  const change = normalizeSuppliedContact(supplied);

  // Step 4b. The SUPPLIED change must agree with the SIGNED kind, and this check
  // is load-bearing rather than belt-and-braces. `canonicalContactChange` puts
  // `kind` first in the hashed tuple, so the hash below binds the kind the
  // PREVIEW chose — but a caller can present a payload minted for one operation
  // beside a change describing another, and the two would then disagree about
  // how destructive the request is. A disagreement the caller authored must
  // resolve in favour of neither. It runs before the hash so the cheapest
  // comparison happens first; both reach no network either way.
  if (change.kind !== payload.k) throw new ConfirmationInvalidError();

  // Step 5. Over the CANONICALISED change, so a caller that rebuilt the object
  // in a different key order is not refused for it, and a caller that altered
  // one value is. `canonicalContactChange` is what keeps "leave this field
  // alone" and "clear this field" from hashing the same, which is the swap this
  // comparison would otherwise admit after the user had approved the preview.
  if (
    !(await changeHashMatches(await contactChangeHashOf(change), payload.h))
  ) {
    throw new ConfirmationInvalidError();
  }

  // Step 6. A KV read and a KV write, before any DAV request.
  await reserveConfirmation(
    env.CONFIRM_KV,
    principal.userId,
    payload.j,
    payload.x,
  );

  // Step 7. The target comes from the payload's own `c` and `o`, never from a
  // re-supplied argument.
  const ref: ContactRef = {
    addressBookUrl: payload.c,
    objectUrl: payload.o,
  };

  // The dispatch. Both arms exist now, and everything above this line ran
  // identically for each of them — which is the whole shape the gate was built
  // for.
  if (payload.k === "create") {
    // The uid comes out of the SIGNED object url rather than being minted
    // afresh, so the card that gets written is the card the preview named.
    // Unreachable through a payload this server minted —
    // `planContactCreateTarget` builds the url from a uid and a `.vcf` suffix —
    // but a non-null assertion would be a claim about a caller this function
    // cannot see.
    const uid = contactUidFromObjectUrl(payload.o);
    if (uid === null) throw new ConfirmationInvalidError();

    // **A create confirmation carries NO ETag, and that is enforced rather than
    // merely documented.** `ConfirmPayload.e` states the invariant — null ONLY
    // for a create — because the type cannot: the field is `string | null` for
    // every kind. A create whose payload names an ETag is one this server did
    // not mint, and the reason to refuse it rather than ignore the field is that
    // the two preconditions are OPPOSITES: `If-Match` asserts the resource is
    // unchanged, `If-None-Match: *` asserts it does not exist. A payload holding
    // both intentions is one whose author disagreed with itself about which
    // operation this is.
    if (payload.e !== null) throw new ConfirmationInvalidError();

    const written = await createContact(env, principal, davFetch, {
      ref,
      vcfBody: buildContactCard(uid, change),
    });

    const fields = changedContactFields(change);

    return {
      applied: written.created,
      id: written.id,
      changedFields: fields,
      fieldCount: fields.length,
      change,
      // The SAME composer with the tense supplied, never a second sentence.
      // `scripts/forbidden-tokens.mjs` holds the composer at exactly one
      // definition site with a two-directional count, and the two lines are
      // comparable by construction: strip the leading verb and the remainders
      // are byte-identical.
      confirmationLine: composeConfirmationLine(
        {
          kind: "create",
          noun: "contact",
          name: displayNameForChange(change),
          alsoRemoved: null,
          fieldCount: null,
          recipientCount: null,
          // NULL. A contact has no reminders. Present and null rather than
          // absent, on `ConfirmationSummary`'s own rule: an operation that cannot
          // touch one says so, and a field that can be ABSENT is a field a later
          // build reads as `undefined`.
          alarms: null,
          reply: null,
        },
        "did",
      ),
    };
  }

  // **An update confirmation MUST carry an ETag, and that is enforced rather
  // than merely documented.** The create arm's mirror image, and the pair is
  // what makes `ConfirmPayload.e`'s "null ONLY for a create" invariant real: the
  // type cannot express it, because the field is `string | null` for every kind.
  // An update whose payload names no version is one this server did not mint,
  // and the reason to refuse rather than write unconditionally is the whole of
  // CONW-06 — an unconditional overwrite is the raced write nobody can detect.
  if (payload.e === null) throw new ConfirmationInvalidError();

  // Step 7a. RE-READ the card. **The commit holds no card bytes and must not**:
  // carrying them through the token would put a card's whole text inside a value
  // the caller holds and can alter, and hashing the serialized card instead is
  // the hazard `canonicalChange`'s docstring names — a revision property makes
  // two serializations of one change differ.
  const fetched = await getContactWithEtag(env, principal, davFetch, ref);

  // Step 7b. The cheap refusal. A card edited on the phone between the preview
  // and now costs ONE read rather than a write the server was always going to
  // refuse — and the user is told the same `stale_resource` either way.
  //
  // Byte equality, quotes included. No normalisation of weak validators, no
  // trimming: this project has no entity-tag comparison rule and inventing one
  // here would be deciding, in a commit path, that two versions iCloud
  // distinguishes are the same.
  if (fetched.etag !== payload.e) throw new DavStaleResourceError();

  // Step 7c. Patch the bytes just READ, never a card built from a parse. This is
  // PITFALLS #39: `ParsedContact` sees eight properties, so a card rebuilt from
  // one deletes the photo, the grouped label pair and every `X-` property on a
  // routine telephone-number edit — on the account and on every device the user
  // owns, silently.
  const vcfBody = patchContactCard(fetched.body, change);

  // Step 7d. The write, conditional on the SIGNED entity tag and not the re-read
  // one. The two agree by step 7b, so this is not belt-and-braces: passing the
  // signed value is what makes the conditional header carry the version the USER
  // approved against, and it is the only thing that catches a card changing
  // between THIS SERVER'S own read and its own write — a window step 7b
  // structurally cannot see, because it happened after step 7b ran.
  const written = await updateContact(
    env,
    principal,
    davFetch,
    ref,
    vcfBody,
    payload.e,
  );

  // Two requests on this leg, serial, and the fan-out rule's own text permits
  // exactly this by name: it bans CONCURRENCY and not request count, "because a
  // patch needs the whole resource and rebuilding drops every component it did
  // not rebuild".
  const fields = changedContactFields(change);

  return {
    applied: written.applied,
    id: written.id,
    changedFields: fields,
    fieldCount: fields.length,
    change,
    // The SAME composer with the tense supplied, never a second sentence. The
    // name comes off the card this commit itself fetched, so a card renamed
    // between the preview and now is named here as it was called at THIS line's
    // own moment — which is the behaviour the server-level instructions already
    // tell a client to expect of the calendar's pair.
    confirmationLine: composeConfirmationLine(
      {
        kind: "update",
        noun: "contact",
        name: fetched.detail.displayName,
        alsoRemoved: null,
        fieldCount: fields.length,
        recipientCount: null,
        // NULL. A contact has no reminders. Present and null rather than
        // absent, on `ConfirmationSummary`'s own rule: an operation that cannot
        // touch one says so, and a field that can be ABSENT is a field a later
        // build reads as `undefined`.
        alarms: null,
        reply: null,
      },
      "did",
    ),
  };
}

/**
 * Register the contact write tools on a per-request server instance.
 *
 * Called from `registerContactsTools` rather than from `src/mcp/server.ts`, and
 * the module header says why: the description-ceiling loop in
 * `test/dav-tools.test.ts` reaches the contacts surface through that one
 * registrar, so a registration added behind it is measured by construction.
 *
 * ## The description convention
 *
 * The rule for where a fact lives is the one `./mail.ts` records and
 * `./calendar.ts` follows: a RELATION between two parameters goes in the tool
 * description, a fact about ONE parameter goes on that parameter's own describe
 * call. So the create description names `contacts_commit` — the relation is
 * undiscoverable from either tool alone — while the absent-versus-null rule and
 * the whole-list replacement rule live on the parameters they are facts about.
 *
 * Every per-parameter description states the CONSEQUENCE rather than the rule,
 * because a model reading "nullable" learns nothing and a model reading "null
 * clears it; omit to leave it" learns what it is about to do to somebody's
 * address book.
 */
export function registerContactsWriteTools(
  server: McpServer,
  davFetch: DavFetch,
  principal: Promise<Principal>,
): void {
  const entryList = (what: string) =>
    z
      .array(
        z.object({
          value: z.string().describe(`One ${what}.`),
          types: z
            .array(z.string())
            .optional()
            .describe("Type labels, e.g. HOME, WORK, CELL. Omit for none."),
        }),
      )
      .nullable()
      .optional();

  const changeShape = {
    kind: z.enum(["create", "update"]),
    formattedName: z
      .string()
      .nullable()
      .optional()
      .describe("The display name. Null clears it; omit to leave it."),
    name: z
      .object({
        family: z.string().nullable().optional(),
        given: z.string().nullable().optional(),
        additional: z.string().nullable().optional(),
        prefix: z.string().nullable().optional(),
        suffix: z.string().nullable().optional(),
      })
      .nullable()
      .optional()
      .describe(
        "The structured name, whole. Supplying it REPLACES all five parts; " +
          "null clears it; omit to leave it.",
      ),
    organisation: z
      .array(z.string())
      .nullable()
      .optional()
      .describe(
        "The organisation's parts, whole. Supplying it REPLACES them; null " +
          "clears it; omit to leave it.",
      ),
    address: z
      .object({
        poBox: z.string().nullable().optional(),
        extended: z.string().nullable().optional(),
        street: z.string().nullable().optional(),
        locality: z.string().nullable().optional(),
        region: z.string().nullable().optional(),
        postalCode: z.string().nullable().optional(),
        country: z.string().nullable().optional(),
      })
      .nullable()
      .optional()
      .describe(
        "The postal address, whole. Supplying it REPLACES every part; null " +
          "clears it; omit to leave it.",
      ),
    note: z
      .string()
      .nullable()
      .optional()
      .describe("The note. Null clears it; omit to leave it."),
    emails: entryList("email address").describe(
      "The complete list. Supplying it REPLACES every email on the card; " +
        "null or an empty list removes them all; omit it to leave them alone.",
    ),
    tels: entryList("telephone number").describe(
      "The complete list. Supplying it REPLACES every number on the card; " +
        "null or an empty list removes them all; omit it to leave them alone.",
    ),
  };

  server.registerTool(
    "contacts_create",
    {
      // **Why the duplicate list gets words here at all.** A list of names with
      // no account of itself reads as an instruction — "here are some people",
      // and a model with no statement of what they mean is left to guess whether
      // it should be merging into one of them. So the description states the
      // CONSEQUENCE, in the register the rest of this registrar uses: these cards
      // already hold something you supplied, nothing was merged, and committing
      // adds a card. The per-tool ceiling is 280 characters and the untrusted
      // notice is 133 of them, which is why the original "returns what would be
      // created plus a confirmation" was compressed rather than extended: a
      // sentence that does not fit is a sentence nobody reads.
      description:
        "Preview a new contact. Writes nothing. duplicateCandidates: cards " +
        "already holding a supplied value; none merged. Commit with " +
        `contacts_commit. ${CONTACTS_UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        addressBookId: z
          .string()
          .describe("Opaque address book id from contacts_search."),
        change: z
          .object(changeShape)
          .describe("The card to create. Pass it back to contacts_commit unaltered."),
      }),
    },
    async ({ addressBookId, change }) => {
      try {
        // Who this call acts for. First, so a refused principal reads
        // `auth_failed` before anything else is looked at (D-27).
        const actor = await principal;
        return contactPreviewToolResult(
          await withContactConfirmationBoundary(() =>
            buildContactCreatePreview(
              actor,
              davFetch,
              addressBookId,
              change as SuppliedContactChange,
            ),
          ),
        );
      } catch (err) {
        return davErrorResult(err);
      }
    },
  );

  server.registerTool(
    "contacts_update",
    {
      // **The one sentence this description must carry is the one about what
      // SURVIVES.** CardDAV has no partial update, so the half of PITFALLS #39
      // that no code path can refuse is a model helpfully supplying a complete
      // contact object assembled from what it remembers — every field it forgot
      // would become a deletion. The input here is a DIFF, and saying so plus
      // naming `preservedPropertyCount` is what tells a model it does not need
      // to send the whole card and must not try. The per-tool ceiling is 280
      // characters and the untrusted notice is 133 of them, so this is the
      // shortest form of that fact that still says it.
      description:
        "Preview one change to an existing contact. Writes nothing. Send ONLY " +
        "changed fields; omitted ones survive. Commit with contacts_commit. " +
        `${CONTACTS_UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        // `id`, matching `contacts_get` one module over, and NOT `contactId`.
        // That spelling is on an explicit forbidden list in
        // `test/dav-tools.test.ts`, because on a CALENDAR write a `contactId`
        // parameter would mean "derive the attendee list from this person" —
        // PITFALLS #12's autonomous-schedule shape, and Conventions §2 point 5.
        // Here the id names the resource being written rather than a source of
        // values, which is `contacts_get`'s own role for the same spelling; the
        // rule is left exactly as strict as it was rather than taught an
        // exception for a tool that never needed one.
        id: z
          .string()
          .describe("Opaque contact id from contacts_search or contacts_get."),
        change: z
          .object(changeShape)
          .describe(
            "The fields to change, and nothing else. Pass it back to " +
              "contacts_commit unaltered.",
          ),
      }),
    },
    async ({ id, change }) => {
      try {
        // Who this call acts for. First, so a refused principal reads
        // `auth_failed` before anything else is looked at (D-27).
        const actor = await principal;
        return contactPreviewToolResult(
          await withContactConfirmationBoundary(() =>
            buildContactUpdatePreview(
              actor,
              davFetch,
              id,
              change as SuppliedContactChange,
            ),
          ),
        );
      } catch (err) {
        return davErrorResult(err);
      }
    },
  );

  server.registerTool(
    "contacts_commit",
    {
      // It names BOTH previews, because the relation is undiscoverable from
      // either tool alone and a model told only about the create would be left
      // guessing whether an update token belongs here. Which operation actually
      // runs is read from the SIGNED payload rather than from which tool was
      // called, so naming both here reports the wiring rather than widening it.
      description:
        "Apply what contacts_create or contacts_update previewed. Pass its " +
        `confirmToken and its change back unaltered. ${CONTACTS_UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        // The REASON goes on the parameter that carries it. This is the sentence
        // a model reads at the moment it is about to apply a change somebody has
        // just agreed to, which is the last point at which the agreement can
        // have been obtained on a false description.
        confirmToken: z
          .string()
          .describe(
            "The confirmToken from contacts_create or contacts_update, " +
              "unaltered. Before you " +
              "pass this back, the user must have seen the preview's " +
              "confirmationLine word for word: it is the sentence this server " +
              "wrote about what is about to happen, and a summary of your own " +
              "is how somebody agrees to something other than what they were " +
              "shown. This call answers with the same sentence in the past " +
              "tense. It can be spent only once.",
          ),
        change: z
          .object(changeShape)
          .describe(
            "The change object contacts_create returned, passed back " +
              "unaltered. Altering any value is refused before anything is sent.",
          ),
      }),
    },
    async ({ confirmToken, change }) => {
      try {
        // Who this call acts for. First, so a refused principal reads
        // `auth_failed` before anything else is looked at (D-27).
        const actor = await principal;
        return contactCommitToolResult(
          await withContactConfirmationBoundary(() =>
            applyContactCommit(
              actor,
              davFetch,
              confirmToken,
              change as SuppliedContactChange,
            ),
          ),
        );
      } catch (err) {
        return davErrorResult(err);
      }
    },
  );
}
