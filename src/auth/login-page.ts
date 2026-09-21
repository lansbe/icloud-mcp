// Every byte a person sees at /authorize, and nothing else.
//
// This is the only user interface in the project, and since Phase 11 it asks a
// real person — a family member or a friend — for their own Apple ID and an
// app-specific password belonging to their own Apple account. Rendering lives
// here rather than in `src/auth/login-handler.ts` because that file is already
// 32 KB of flow control and this phase adds a credential form and three limiter
// layers to it. The split is a locked decision, not a tidiness.
//
// **The page this file renders is an APPROVED design contract**, signed off on
// seven dimensions and recorded in
// `.planning/phases/11-login-page-and-the-switch/11-UI-SPEC.md`. The copy, the
// ordering, the colour tokens, the type scale, the spacing scale and the
// accessibility rules below are implementations of that contract rather than
// choices made here. Changing one of them is a change to a decision.
//
// Five properties are worth knowing before reading the markup, because each one
// is load-bearing and none of them is obvious from the code alone.
//
// **No script, no image, no icon, no web font.** That is what lets the policy
// header stay as narrow as it is: `default-src 'none'` stands in front of
// everything, so the inline style is safe — CSS exfiltration needs an outbound
// request and no directive permits one. It also means there is no pending
// state, and that too is decided: the submit button is never disabled or
// relabelled while the check runs, and the mitigation is the button's help line
// plus the server-side limiters. Do not add a script to fix that.
//
// **No submitted value is ever rendered back.** Neither credential field
// carries a pre-filled-value attribute on any path, and no failure body has an
// interpolation slot. Both boxes come back empty after a failure, so re-typing
// is the only recovery, and the second line of the failure copy says so out
// loud rather than letting it read as a bug.
//
// **One failure string on the credential path.** A badly-shaped app password,
// an unlisted address, a malformed Apple ID, a wrong password and a per-target
// limiter trip all render the SAME body at the same 401. The owner decided that
// on 2026-09-20 with the cost in view: a family member who mistypes gets no
// signal telling a typo apart from a refusal. Do not split it to "improve the
// error" — that reverses the decision. The Apple-throttle message is the sole
// exception and it can only be built after Apple has already answered.
//
// **Which is why the password field's help copy is load-bearing.** With every
// credential failure answering the same silent string, that one line is the
// only place on the page a reader learns what to type. It used to name a shape
// — sixteen letters, an example with dashes, and a claim that the dashes were
// optional. That claim was only ever true if Apple said so, and Apple has never
// published a format for these values; the shape came from one observed sample.
// Spike S5, which would have measured it, was declined by the owner on
// 2026-09-20, and the handler stopped editing the submitted value in the same
// change. So the copy now tells the reader to paste the value exactly as Apple
// showed it, which is advice this project can actually stand behind.
//
// Keep it above the field, where it is read before typing rather than after
// submitting, and do not shorten it. If a future session reinstates a shape
// claim here, it owes the measurement first — `couldBeAppPassword` in
// `./login-handler` says how to take it.
//
// **The page must be recognisably NOT Apple's.** No Apple logo, no wordmark, no
// Apple system blue, no imitation of Apple's own sign-in page. A page that asks
// for an Apple credential while dressed as Apple teaches the reader that
// Apple-looking pages deserve Apple credentials, which is the habit every
// credential-phishing attack depends on. Trust comes from the copy saying
// plainly what this is, who is asking, and where it will send them.
//
// **This module holds no logging call and must never acquire one**
// (Convention 4). Nothing here reads a password, and nothing here can: the page
// is handed a query string and a client identity, and that is all.
//
// ---------------------------------------------------------------------------
// On the import cycle with `./login-handler`, which is deliberate and safe.
//
// This module imports the destination display helper and the two field names
// from the handler; the handler imports the renderer, the header constant and
// the refusal bodies from here. That cycle exists ON PURPOSE. The allowlist
// check and the consent line must read the SAME derived origin — a second
// derivation would let the page name an origin the check never looked at, which
// is a mitigation lying about what it mitigated — and the field names must be
// the same strings the form writes and the handler reads.
//
// It resolves because nothing crosses the cycle at module-evaluation time. Every
// imported binding here is used inside `renderForm`'s body, and every binding
// the handler imports from here is used inside a request. Neither module calls
// into the other while it is still initialising, so the load order does not
// matter. Keep it that way: a top-level call across this boundary would turn a
// working cycle into an undefined binding at cold start.
// ---------------------------------------------------------------------------

import type { ClientIdentity } from "./login-handler";
import {
  APP_PASSWORD_FIELD,
  APPLE_ID_FIELD,
  displayDestination,
} from "./login-handler";

/**
 * The security headers every response this handler serves must carry.
 *
 * Exported for the reason `UNCONFIGURED_BODY` is exported: the table test then
 * asserts against the value the handler actually serves rather than a second
 * copy of four header values that could drift from it. This is the first shared
 * header constant in this project — every response built before this phase
 * spelled its headers inline, and two of them carried no caching header at all.
 *
 * What each one is for:
 *
 * `default-src 'none'` closes everything, including scripts, which is why the
 * no-script rule above is worth keeping. `style-src 'unsafe-inline'` is safe
 * precisely because that default stands in front of it: CSS-based exfiltration
 * needs an outbound request and no directive permits one. `form-action 'self'`
 * is the quiet one that matters — it stops an injected form from posting these
 * two fields anywhere else. `frame-ancestors 'none'` and the legacy framing
 * header are the clickjacking pair, and they are on EVERY response rather than
 * only the form. `no-referrer` keeps the authorization query out of an outbound
 * request's referrer. `no-store` is the one that matters most on the two
 * redirects: the success redirect's location header carries the authorization
 * code, and a cached copy of that redirect is a cached copy of a
 * credential-equivalent.
 *
 * Spread this FIRST at every construction site and let the site's own headers
 * follow, so a site can never silently drop one of the four.
 */
export const RESPONSE_HEADERS: Readonly<Record<string, string>> = {
  "content-security-policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
};

/**
 * The ONE body for every failure on the credential path, both of its lines.
 *
 * A badly-shaped app-specific password, an address that is not on the allow
 * list, a malformed or empty Apple ID, a password Apple turned down, and a trip
 * of this server's own per-target limiter all render exactly this. Not a
 * variant of it, not a character of difference between any two of its causes.
 *
 * The per-target limiter trip is the member most worth naming, because it is
 * the one a reader is tempted to give its own status: a 429 that only ever
 * appears for a listed address is a membership oracle, which is precisely what
 * this phase's success criteria forbid. It renders this body at this status
 * like every other member.
 *
 * Exported so the byte-identical-bodies assertion is an equality against the
 * value the page actually serves, rather than against a retyped sentence that
 * could drift from it.
 *
 * The second line is not decoration and must not be dropped to shorten the
 * error. No submitted value is ever rendered back, so both boxes really are
 * empty and re-typing really is the only recovery; saying so is what stops that
 * reading as a bug.
 */
export const CREDENTIAL_FAILURE_BODY: readonly string[] = [
  "That did not work. Check the address and the password, then try again.",
  "Both boxes are empty again. This page never keeps what you typed.",
];

/**
 * The one message on the credential path that differs, and only after Apple.
 *
 * It may be built ONLY once Apple has already answered. That is what makes it
 * safe: reaching Apple at all already means the address was on the allow list,
 * so this message reveals nothing the round trip had not already revealed. The
 * criterion about a per-target trip never disclosing list membership binds THIS
 * SERVER'S OWN limiter, not Apple's reply — the two are different events and
 * only the first of them is a leak.
 *
 * It exists because the generic body sends people to Apple to make a new
 * app-specific password, which is both useless and more load on the thing that
 * is already refusing to answer. Telling them to wait is the honest instruction
 * and the cheaper one.
 *
 * The handler does not build this state yet; branching on the throttle error
 * type is plan 11-04's, and this page renders the state it will pass.
 */
export const APPLE_THROTTLE_BODY: readonly string[] = [
  "Apple is not answering right now. Wait a few minutes and try again. Making a new app-specific password will not help.",
];

/**
 * The plain-text body served when one source connection has tried too often.
 *
 * Unchanged wording, moved here so the copy for this surface lives in one file.
 * It is NOT a credential-path failure: it is keyed by the connecting source
 * rather than by the address being tried, so it carries no information about
 * who is on the allow list, and it is answered before the credential check
 * exists to leak anything. That is why it is the one refusal allowed a status
 * of its own.
 *
 * **The design contract contradicted itself here, and this is where that was
 * resolved.** Its failure-states table gives this surface a longer sentence,
 * while its list of responses that are NOT restyled names this one with "same
 * wording, same status". Plan 11-02 kept the old sentence and said why: the
 * limiter behind it was about to be replaced, so rewording a body that was
 * about to be rewritten bought nothing. Plan 11-05 is that replacement, so the
 * deferral is over and the table wins.
 *
 * The table wins on two grounds. It is the SPECIFIC instruction — it quotes the
 * exact string for exactly this response — while the not-restyled list is about
 * STYLING, and its point is that this answer stays plain text at the same
 * status rather than becoming a designed page. Both of those still hold. And
 * the longer sentence says the thing that matters: the refusal is about the
 * CONNECTION, not about what was typed. Somebody who sees "too many attempts"
 * straight after typing a password reasonably concludes their password was
 * counted and goes to Apple to make a new one. Naming the connection is the
 * correction.
 *
 * **The wait deliberately over-states the window.** The binding's window is
 * sixty seconds, and this says a few minutes. The counter is per Cloudflare
 * location and its epochs are wall-clock aligned, so "sixty seconds from now"
 * is not a promise this server can keep; somebody who comes back too early
 * spends another attempt for nothing. The machine-readable answer is the
 * `retry-after` header, which carries the real figure. Rounding up in prose and
 * being exact in the header is the honest pair.
 */
export const SOURCE_REFUSAL_BODY =
  "Too many sign-in attempts from this connection. Try again in a few minutes.";

/** Which failure the page came back with, or `null` for a first load. */
export type LoginFailure = "credentials" | "throttled" | null;

/**
 * One always-visible explainer section.
 *
 * `steps` renders as an ordered list above the paragraphs, because the one
 * section that has steps is the one where the order is the instruction.
 */
export interface ExplainerSection {
  readonly heading: string;
  readonly steps: readonly string[];
  readonly paragraphs: readonly string[];
}

/**
 * The four things the page must explain, in the order it explains them.
 *
 * **Always visible. Never inside a disclosure element, never behind a
 * "learn more".** The requirement is that the page EXPLAINS an app-specific
 * password, and an explanation nobody opened is an explanation nobody read.
 * These sit below the fold on a phone and that is acceptable; collapsing them
 * is not.
 *
 * Exported so the test asserts every heading and every body against the value
 * the page actually renders rather than against eight retyped paragraphs. A
 * count would pass when two sections merge, which is why the test asserts the
 * strings.
 *
 * The invitation sentence in the third section is there because it is true, and
 * because leaving it out would make the list of what this thing can do quietly
 * incomplete. The "cannot send mail" sentence sits next to it so the pair reads
 * as the honest boundary it is.
 */
export const EXPLAINER_SECTIONS: readonly ExplainerSection[] = [
  {
    heading: "What is an app-specific password?",
    steps: [],
    paragraphs: [
      "It is a separate password Apple makes for an app that is not Apple's. It is not your Apple ID password. You can delete it later without changing anything else about your account.",
    ],
  },
  {
    heading: "How to make one",
    steps: [
      "Go to account.apple.com and sign in.",
      "Open Sign-In and Security, then App-Specific Passwords.",
      "Add one, name it iCloud MCP, and copy what Apple shows you.",
    ],
    paragraphs: [
      "You need two-factor authentication turned on. Apple shows the password once, so copy it before you close the box.",
    ],
  },
  {
    heading: "What this server can do afterwards",
    steps: [],
    paragraphs: [
      "It can read your mail, your calendar and your contacts. It can put a draft in your Drafts folder, and add or change calendar events. If you ask it to invite people to an event, Apple sends those invitations. It cannot send mail. Your password is stored encrypted on this server and is used only to talk to Apple.",
    ],
  },
  {
    heading: "How to cut it off",
    steps: [],
    paragraphs: [
      "Go back to App-Specific Passwords at account.apple.com and delete the one you made. This server stops working straight away. Nothing else about your account changes.",
    ],
  },
];

/**
 * How many characters of a registered client's name the page will show.
 *
 * Registration is unauthenticated, so the name is an arbitrary attacker-chosen
 * string. A few thousand characters of it pushes the destination line and the
 * not-an-Apple-page line off a phone screen, which defeats the consent block by
 * BURIAL rather than by removal — the values are all still on the page, and
 * none of them is where the reader will look.
 */
const CLIENT_NAME_DISPLAY_LIMIT = 80;

/**
 * Escape the five characters that could otherwise rewrite the markup.
 *
 * Moved here unchanged from the handler. Every interpolation of an outside
 * value goes through it — the client name, the destination origin, and the raw
 * query round-tripped in the hidden field.
 */
export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * Cut a display string to the limit, with a trailing ellipsis.
 *
 * **This runs BEFORE escaping, never after, and the order is the whole point.**
 * Escaping first and cutting at 80 can slice an entity in half — `&amp;`
 * becomes `&am` — which is not an injection but is a visible mangling of a name
 * the reader is being asked to recognise. Cutting first also makes the 80 a
 * count of characters the reader sees rather than a count of markup.
 *
 * It counts code points rather than code units, so a name ending in an emoji or
 * any other astral character is cut between characters instead of between the
 * two halves of one. A lone surrogate would render as a replacement glyph,
 * which is the same mangling this function exists to avoid, one layer down.
 *
 * Truncation is display-only. Nothing the server decides on is derived from the
 * name, so nothing downstream sees the shortened form.
 */
function truncateForDisplay(value: string): string {
  const characters = [...value];
  if (characters.length <= CLIENT_NAME_DISPLAY_LIMIT) return value;
  return `${characters.slice(0, CLIENT_NAME_DISPLAY_LIMIT).join("")}…`;
}

/** Apple's account site, linked wherever this page's own copy names it. */
const APPLE_ACCOUNT_HOST = "account.apple.com";

/**
 * A new tab, and no opener or referrer.
 *
 * A new tab because the reader is being sent away mid-form, and a same-tab
 * navigation throws away whatever they had already typed. No opener because the
 * opened page must not be able to reach back at this one.
 */
const APPLE_ACCOUNT_LINK = `<a href="https://account.apple.com" target="_blank" rel="noopener noreferrer">account.apple.com</a>`;

/**
 * Escape one of THIS MODULE'S OWN copy strings and link Apple's account site.
 *
 * The substitution is applied only to the constants declared above, never to
 * any value that arrived on a request. That distinction is the whole safety
 * argument: putting markup back into a string after escaping it would be a hole
 * if the string were attacker-chosen, and these are source constants that no
 * request can influence. Untrusted values go through `escapeHtml` alone.
 */
function copy(text: string): string {
  return escapeHtml(text).replaceAll(APPLE_ACCOUNT_HOST, APPLE_ACCOUNT_LINK);
}

/** The id of the alert region, added to both inputs when it is present. */
const ERROR_REGION_ID = "login-error";

/** The lines a given failure state shows, or none on a first load. */
function failureLines(failure: LoginFailure): readonly string[] {
  if (failure === "credentials") return CREDENTIAL_FAILURE_BODY;
  if (failure === "throttled") return APPLE_THROTTLE_BODY;
  return [];
}

/**
 * The whole style block, as one string.
 *
 * Three type sizes (14, 16, 20) and two weights (400, 600). Every spacing value
 * is a multiple of four drawn from the declared scale, with no exceptions. Two
 * media queries and no others: one swaps the colour tokens for the dark scheme,
 * one adapts the card at phone width.
 *
 * Two properties are removed from what this page used to do, and both removals
 * are deliberate changes to working code:
 *
 * The full-viewport grid and its vertical centering are GONE. The page is now
 * taller than a phone viewport, and a centred item that overflows clips its own
 * top — which loses the heading, the client name and the destination first, in
 * that order. Top-aligned never clips.
 *
 * The translucency that used to dim body copy is GONE. It landed around 4.4:1
 * and shifted with whatever sat behind it; the muted token is a measured 7.2:1
 * in light and 7.0:1 in dark. Dimming text with translucency is banned on this
 * page, not merely avoided.
 *
 * The two inputs are 16px and that is not negotiable. iOS Safari zooms the page
 * whenever a focused input is below 16px, which throws the consent block off
 * screen at the exact moment the person is about to type a credential.
 *
 * The accent token is reserved for the submit button's background, the focus
 * ring and the two links. Nothing else is ever accent-coloured, because the
 * submit button is the page's single focal point and the only full-width block
 * of solid colour.
 */
const STYLE = `
  :root {
    color-scheme: light dark;
    --bg: #F7F7F8;
    --surface: #FFFFFF;
    --border: #D9DBE0;
    --text: #1D1D1F;
    --muted: #55575C;
    --accent: #0B63CE;
    --on-accent: #FFFFFF;
    --danger: #B3261E;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #161618;
      --surface: #1F1F23;
      --border: #3A3A40;
      --text: #F2F2F3;
      --muted: #A8A9AE;
      --accent: #6FB2FF;
      --on-accent: #10243B;
      --danger: #FF8A80;
    }
  }
  *, *::before, *::after { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 48px 16px;
    background: var(--bg);
    color: var(--text);
    font: 400 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  main {
    max-width: 480px;
    margin: 0 auto;
    padding: 32px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
  }
  h1 { font-size: 20px; font-weight: 600; line-height: 1.3; margin: 0 0 16px; }
  h2 { font-size: 16px; font-weight: 600; line-height: 1.3; margin: 0 0 8px; }
  p { margin: 0 0 16px; }
  a { color: var(--accent); }
  .lead { margin-bottom: 16px; }
  .consent { margin: 0 0 16px; }
  .consent p, .not-apple { font-size: 14px; color: var(--muted); margin: 0 0 4px; }
  .not-apple { margin: 0 0 16px; }
  .client, .dest { overflow-wrap: anywhere; }
  .error {
    border-left: 3px solid var(--danger);
    padding-left: 12px;
    margin: 0 0 16px;
    color: var(--danger);
  }
  .error p { margin: 0 0 4px; font-size: 14px; }
  .error p:last-child { margin-bottom: 0; }
  label {
    display: block;
    font-size: 14px;
    font-weight: 600;
    line-height: 1.4;
    margin: 0 0 4px;
  }
  input {
    display: block;
    width: 100%;
    min-height: 44px;
    padding: 12px 16px;
    font: 400 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
    color: var(--text);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .help {
    font-size: 14px;
    color: var(--muted);
    margin: 8px 0 16px;
    overflow-wrap: anywhere;
  }
  button {
    display: block;
    width: 100%;
    min-height: 48px;
    padding: 12px 16px;
    font: 600 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
    color: var(--on-accent);
    background: var(--accent);
    border: 0;
    border-radius: 8px;
    cursor: pointer;
  }
  .explainer { margin-top: 24px; }
  .explainer section { margin-top: 32px; }
  .explainer p, .explainer li { font-size: 14px; overflow-wrap: anywhere; }
  .explainer ol { margin: 0 0 16px; padding-left: 16px; }
  .explainer li { margin-bottom: 4px; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  @media (max-width: 480px) {
    body { padding: 24px 16px; }
    main {
      padding: 24px;
      border-radius: 0;
      border-left: 0;
      border-right: 0;
    }
  }
`;

/** One explainer section, as markup. */
function renderSection(section: ExplainerSection): string {
  const steps =
    section.steps.length === 0
      ? ""
      : `<ol>${section.steps.map((step) => `<li>${copy(step)}</li>`).join("")}</ol>`;
  const paragraphs = section.paragraphs
    .map((paragraph) => `<p>${copy(paragraph)}</p>`)
    .join("");
  return `<section><h2>${copy(section.heading)}</h2>${steps}${paragraphs}</section>`;
}

/**
 * The login page, for a first load or for either failed render.
 *
 * `query` is the raw authorization query, round-tripped through a hidden field
 * so the POST re-runs the provider's own client, redirect-URI, response-type
 * and PKCE validation against it. A tampered hidden field is then rejected by
 * the library rather than trusted by this server.
 *
 * Order on the page is fixed and is not a suggestion: heading, lead, the
 * consent block naming the client and then the destination origin, the
 * not-an-Apple-page line, the error region when a previous attempt failed, the
 * form, then the four explainer sections. The consent block stays ABOVE the
 * credential fields — do not move it, collapse it, or put it behind a
 * disclosure. It is the control that lets a person tell an attacker's client
 * from their own before they type anything.
 *
 * **Neither credential input carries a pre-filled-value attribute on any path**,
 * and nothing the reader submitted reaches this function at all. The only
 * values interpolated are the round-tripped query, the client's registered name
 * and the destination origin.
 *
 * Accessibility, in the three places it is doing real work:
 *
 * Every input has a real label element and a help paragraph it points at
 * through its describedby attribute. When a previous attempt failed, the error
 * region's id is added to BOTH inputs' describedby, so the reason is announced
 * when focus lands on the field rather than only when the region is passed.
 *
 * After a credential failure the invalid marker goes on BOTH inputs,
 * unconditionally, and is never narrowed to one even when the server knows
 * which check failed. Putting it on the password alone would rebuild the
 * shape-specific signal the owner removed, in the accessibility tree. After the
 * Apple-throttle failure it goes on neither, because nothing the reader typed
 * was rejected.
 *
 * The document title changes on a failed render, and that change is the only
 * signal a screen-reader user gets that the page came back different. It is
 * cheap and it is the whole no-script accessibility budget.
 *
 * Every failed render is 401, the throttle case included. One status for both
 * removes any need to prove a second one does not leak.
 */
export function renderForm(
  query: string,
  failure: LoginFailure,
  identity: ClientIdentity,
): Response {
  const lines = failureLines(failure);
  const failed = lines.length > 0;

  // The cut is the INNER expression. See `truncateForDisplay` for why the order
  // is not interchangeable.
  const clientName = escapeHtml(truncateForDisplay(identity.name));
  const destination = escapeHtml(displayDestination(identity.redirectUri));

  const errorRegion = failed
    ? `<div id="${ERROR_REGION_ID}" role="alert" class="error">${lines
        .map((line) => `<p>${copy(line)}</p>`)
        .join("")}</div>`
    : "";

  // Both inputs, or neither. Narrowing this to one field is the thing the
  // unconditional form exists to prevent.
  const invalid = failure === "credentials" ? ` aria-invalid="true"` : "";
  const describes = (helpId: string): string =>
    failed ? `${ERROR_REGION_ID} ${helpId}` : helpId;

  return new Response(
    `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${failed ? "Could not sign in — iCloud MCP" : "Sign in — iCloud MCP"}</title>
<style>${STYLE}</style>
</head>
<body>
<main>
  <h1>Sign in with your Apple ID</h1>
  <p class="lead">This connection can read your iCloud mail, calendar and contacts.</p>
  <div class="consent">
    <p><strong class="client">${clientName}</strong> is asking to connect.</p>
    <p>Signing in sends you to <code class="dest">${destination}</code>.</p>
    <p>If you do not recognise both, close this page.</p>
  </div>
  <p class="not-apple">This is not an Apple page, and Apple did not send you here. Check the web address against the one you were given.</p>
  ${errorRegion}
  <form method="post" action="/authorize">
    <input type="hidden" name="oauth_request" value="${escapeHtml(query)}">
    <label for="apple-id">Apple ID</label>
    <input id="apple-id" name="${APPLE_ID_FIELD}" type="email" autocomplete="username" inputmode="email" autocapitalize="none" autocorrect="off" spellcheck="false" aria-describedby="${describes("apple-id-help")}"${invalid} autofocus required>
    <p class="help" id="apple-id-help">The iCloud Mail address you sign in to Apple with.</p>
    <label for="app-password">App-specific password</label>
    <input id="app-password" name="${APP_PASSWORD_FIELD}" type="password" autocomplete="current-password" autocapitalize="none" autocorrect="off" spellcheck="false" aria-describedby="${describes("app-password-help")}"${invalid} required>
    <p class="help" id="app-password-help">Paste it exactly as Apple showed it to you, dashes and all. Do not type your normal Apple ID password here.</p>
    <button type="submit" aria-describedby="submit-help">Sign in</button>
    <p class="help" id="submit-help">This takes a few seconds while Apple checks the password. Press it once.</p>
  </form>
  <div class="explainer">${EXPLAINER_SECTIONS.map(renderSection).join("")}</div>
</main>
</body>
</html>`,
    {
      status: failed ? 401 : 200,
      headers: {
        ...RESPONSE_HEADERS,
        "content-type": "text/html; charset=utf-8",
      },
    },
  );
}
