// GATE-01: the allow list fails closed, and every way of getting it wrong
// means nobody.
//
// **What this file proves that `test/door.test.ts` does not, and why the two
// claims are different.** This file proves the RULE. It drives `parseAllowList`
// and `isAllowed` straight at the predicate with a table of shapes, one
// expectation per shape, which is both cheaper and far more exhaustive than
// routing every malformed secret through a handler. What it cannot prove is
// that the rule is wired to anything: a parse that answered perfectly while
// nothing consulted it would pass every case below. That is the door test's
// claim, and `test/authorize-login.test.ts` makes the matching one for the
// login page. Three files, three different sentences — and all three are needed,
// because each is satisfied by a server that gets the other two wrong.
//
// **Why a table rather than prose.** The list is a Workers Secret the owner
// writes by hand, and the interesting failures are all typos: a missing bracket,
// a stray comma, a star where a name was meant. Each row below names the looser
// rule it kills, because a negative case with no stated reason is one the next
// person deletes as redundant.
//
// **Fail-closed is the whole design, and it has a cost this file records.** A
// list this server cannot read admits NOBODY, which takes the login page down
// for the owner too. That is deliberate: the other direction opens a server that
// reaches real personal mail to anyone who can authenticate at Apple. The
// recovery — set the secret to a JSON array and deploy — lives in the module's
// own docstring, because the response body is the only diagnostic channel
// Convention 4 leaves and a locked-out owner has nothing else to read.
//
// **This file holds no real value.** Every address sits under `.invalid`, a name
// reserved so that it can never resolve.

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { AllowList } from "../src/auth/allow-list";
import { isAllowed, parseAllowList } from "../src/auth/allow-list";

const ONE = "someone@example.invalid";
const TWO = "another@example.invalid";

/** Fold an address the way the list does, so a case reads what it compares. */
function folded(address: string): string {
  return address.trim().toLowerCase();
}

/** Whether this verdict admits the given address. Reads as the door does. */
function admits(list: AllowList, address: string): boolean {
  return isAllowed(list, folded(address));
}

describe("both sources are actually bound", () => {
  // **The cheapest case in this file and the one it could least do without.**
  // Everything else here drives the parse rule with a string this file wrote,
  // so a rule that answered perfectly while NOTHING BOUND THE SOURCE would pass
  // every one of them. This case reads both halves off the pool's own
  // environment, which is built from `wrangler.jsonc` and
  // `vitest.config.ts` — the same two files a deploy is built from.
  //
  // It also de-risks the namespace id. The tracked template carries a
  // placeholder there, and the claim in that file's comment is that a
  // placeholder is harmless because the pool simulates a namespace by BINDING
  // NAME rather than by id. If that claim is ever wrong, it surfaces here — in
  // the smallest test file in the set — rather than three commits later in a
  // login test, where it would read as something else entirely.

  it("binds the store, and it answers like a namespace", async () => {
    expect(env.ALLOW_LIST_KV, "ALLOW_LIST_KV is not bound").toBeDefined();
    expect(typeof env.ALLOW_LIST_KV.get).toBe("function");
    // A real read against the local namespace, not just a shape check. An
    // absent key answers null, which is also the store's own "nobody" case.
    expect(await env.ALLOW_LIST_KV.get("nothing-is-here")).toBeNull();
  });

  it("binds the seed, and it parses to a named set", () => {
    // Not merely present — USABLE. A seed bound to something the parse rule
    // refuses would make every /authorize test in the suite answer 503, and the
    // failure would look like a handler bug rather than a binding one.
    const list = parseAllowList(env.ALLOWED_APPLE_IDS_SEED);

    expect(list.kind, "the bound seed does not parse to a named set").toBe(
      "some",
    );
    expect(admits(list, "listed-user@example.invalid")).toBe(true);
  });
});

describe("every unusable list means nobody", () => {
  it("refuses a secret that was never provisioned", () => {
    // An unset Workers Secret is `undefined` at runtime. Treating that as open
    // is the single failure this whole type exists to make unspeakable.
    expect(parseAllowList(undefined).kind).toBe("nobody");
  });

  it("refuses an empty string, and whitespace that is not JSON either", () => {
    // An empty binding is as dangerous as an absent one: it is the value the
    // absent one decays to.
    expect(parseAllowList("").kind).toBe("nobody");
    // Whitespace only. `JSON.parse` throws on it, and the throw is caught
    // rather than escaping into the door's `fetch`, where it would be a 500
    // with no challenge instead of a 401.
    expect(parseAllowList("   ").kind).toBe("nobody");
  });

  it("refuses text that is not JSON at all", () => {
    // The likeliest typo by far: the owner writes the address the way they
    // would say it. A rule that fell back to "treat the whole string as one
    // entry" would admit this — and would admit `*` typed without brackets.
    expect(parseAllowList("someone@example.invalid").kind).toBe("nobody");
    expect(parseAllowList("[someone@example.invalid]").kind).toBe("nobody");
    expect(parseAllowList("{").kind).toBe("nobody");
  });

  it("refuses valid JSON that is not an array", () => {
    // A bare JSON string is the case that matters here: `"*"` is valid JSON and
    // five characters from meaning everybody. Requiring an array is what stops
    // one forgotten pair of brackets opening the server.
    expect(parseAllowList('"*"').kind).toBe("nobody");
    expect(parseAllowList('"someone@example.invalid"').kind).toBe("nobody");
    expect(parseAllowList('{"allow":["someone@example.invalid"]}').kind).toBe("nobody");
    expect(parseAllowList("42").kind).toBe("nobody");
    expect(parseAllowList("null").kind).toBe("nobody");
  });

  it("refuses an array with nothing in it", () => {
    // Explicitly nobody, and it reads as the owner having deliberately emptied
    // the list. A rule that treated "no entries" as "no restrictions" would
    // invert the owner's clearest possible statement of intent.
    expect(parseAllowList("[]").kind).toBe("nobody");
  });

  it("refuses an array holding anything that is not a string", () => {
    // One bad entry poisons the WHOLE list rather than being skipped. Skipping
    // would mean a list the owner mistyped silently admits the entries either
    // side of the mistake — which is the shape where a removal fails to remove.
    expect(parseAllowList('[1]').kind).toBe("nobody");
    expect(parseAllowList('["someone@example.invalid", 1]').kind).toBe("nobody");
    expect(parseAllowList('[null]').kind).toBe("nobody");
    expect(parseAllowList('[["someone@example.invalid"]]').kind).toBe("nobody");
  });

  it("refuses an array whose only entries are empty", () => {
    // Empties are dropped, and a list left with nothing is the empty-array case
    // above. Stated as its own row because `[""]` LOOKS like one entry, and a
    // rule that folded the empty string into the set would admit an address of
    // no characters at all.
    expect(parseAllowList('[""]').kind).toBe("nobody");
    expect(parseAllowList('["", "   "]').kind).toBe("nobody");
  });

  it("refuses an array holding an address the folding turns away", () => {
    // Same argument as the non-string row: one unusable entry means nobody
    // rather than being dropped. An address with no at sign, with two, or
    // holding a character outside printable ASCII is not one this server can
    // ever match, so a list containing one cannot be read with confidence.
    expect(parseAllowList('["no-at-sign"]').kind).toBe("nobody");
    expect(parseAllowList('["two@at@signs.invalid"]').kind).toBe("nobody");
    expect(parseAllowList('["@no-local-part.invalid"]').kind).toBe("nobody");
    expect(parseAllowList('["trailing@"]').kind).toBe("nobody");
    expect(parseAllowList(`["${ONE}", "no-at-sign"]`).kind).toBe("nobody");
  });

  it("refuses a star ALONGSIDE a name", () => {
    // THE row this rule is most likely to be loosened on, so it is stated on
    // its own. The value has two plausible readings — "everybody" and "these
    // people, plus a typo" — and one of them opens the server to strangers.
    // When a value has two readings and one is dangerous, the safe one is not a
    // guess: it is the only choice that cannot be wrong in the direction that
    // matters. Answering `everybody` here would be the worst bug in this file.
    expect(parseAllowList(`["*", "${ONE}"]`).kind).toBe("nobody");
    expect(parseAllowList(`["${ONE}", "*"]`).kind).toBe("nobody");
    expect(parseAllowList('["*", "*"]').kind).toBe("nobody");
  });
});

describe("a usable list says who", () => {
  it("opens the server for exactly one star and nothing else", () => {
    // The one value that means everybody. It has to be the whole list, and the
    // whole list has to be it.
    const list = parseAllowList('["*"]');

    expect(list.kind).toBe("everybody");
    expect(admits(list, ONE)).toBe(true);
    expect(admits(list, TWO)).toBe(true);
    // Even "everybody" refuses an address this server cannot read. There is no
    // verdict under which an unfoldable address is acted for.
    expect(isAllowed(list, null)).toBe(false);
  });

  it("holds one good address", () => {
    const list = parseAllowList(`["${ONE}"]`);

    expect(list.kind).toBe("some");
    expect(admits(list, ONE)).toBe(true);
    // Not anybody else. Equality on the whole folded address, never a suffix or
    // a substring test — which is what stops a domain-wide entry existing by
    // accident and what makes a `+tag` variant a different person.
    expect(admits(list, TWO)).toBe(false);
    expect(admits(list, "someone@example.invalid.evil.invalid")).toBe(false);
    expect(admits(list, "notsomeone@example.invalid")).toBe(false);
    expect(admits(list, "someone+tag@example.invalid")).toBe(false);
  });

  it("holds several", () => {
    const list = parseAllowList(`["${ONE}", "${TWO}"]`);

    expect(list.kind).toBe("some");
    expect(admits(list, ONE)).toBe(true);
    expect(admits(list, TWO)).toBe(true);
    expect(admits(list, "third@example.invalid")).toBe(false);
  });

  it("matches an entry the owner typed with padding or capitals", () => {
    // Both sides go through the SAME folding. A set of raw strings would
    // silently refuse a person whose entry the owner typed with a capital or a
    // stray space, and the owner's only clue would be a failed login with a
    // message that says nothing.
    const list = parseAllowList('["  SomeOne@Example.INVALID  "]');

    expect(list.kind).toBe("some");
    expect(admits(list, ONE)).toBe(true);
    expect(admits(list, "  SOMEONE@example.invalid ")).toBe(true);
  });
});

describe("a null address is refused under every verdict", () => {
  // The fail-closed edge, stated against all three members rather than one. An
  // address the folding turned away is refused rather than admitted, and it is
  // refused the same way whether the list is empty, open or named — so no
  // verdict is a back door for one.

  it("is refused by nobody", () => {
    expect(isAllowed(parseAllowList(undefined), null)).toBe(false);
  });

  it("is refused by everybody", () => {
    // The row most worth having. "Everybody" is the one verdict where a reader
    // might expect null to pass, and it must not: an address this server could
    // not read is not an address it can act for.
    expect(isAllowed(parseAllowList('["*"]'), null)).toBe(false);
  });

  it("is refused by a named set", () => {
    expect(isAllowed(parseAllowList(`["${ONE}"]`), null)).toBe(false);
  });
});
