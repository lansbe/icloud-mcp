# Security Policy

iCloud MCP reaches real personal iCloud accounts — mail, calendar, and
contacts. Security is the point of the design, not an afterthought. This
document explains how to report a vulnerability and what the server does and
does not guarantee.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, the impact, and how to reproduce it.

> Maintainer setup: enable this once under **Settings → Code security and
> analysis → Private vulnerability reporting**.

You will get an acknowledgement, a fix or a decision with reasoning, and credit
in the advisory if you would like it. Please allow reasonable time to address
the issue before any public disclosure.

## Supported versions

This is a single-branch project. Security fixes are applied to the `main`
branch. There are no long-lived release branches to back-port to.

## What is a secret, and what is not

Several people can sign in. Each one brings their own Apple ID and their own
Apple app-specific password, and each one reaches only their own account. That
changes where the secrets are, so read this table before the rest.

| Secret | Where it lives | What it is for |
|--------|----------------|----------------|
| Each person's own app-specific password | Inside **their own grant's encrypted props**, and nowhere else | Proving that person to Apple, on their own calls only |
| `CONFIRM_SECRET` | Cloudflare Secrets | The HMAC key for calendar confirmation tokens |
| `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` | Cloudflare Secrets | The R2 S3 API token for presigned attachment uploads |

The server holds no account credential of its own. There is no shared login
password and no Apple identity in the Worker environment. Both existed before
the switch to per-person sign-in; neither does now.

The following are **not** secrets — they are opaque handles that grant nothing
on their own, and they live in configuration:

- The Cloudflare account id (`R2_ACCOUNT_ID`).
- KV namespace ids and the R2 bucket name.
- The deployed hostname.
- The allow-list seed — the owner's own address, held as a config value because
  it is read on every request and a config read is synchronous.

In the public repository these config values are placeholders; the real ones
live only in your git-ignored `wrangler.jsonc`.

## The security model

### The endpoint is authenticated

The Worker's entry point *is* the OAuth provider
(`@cloudflare/workers-oauth-provider`). It owns routing, so the bearer-token
check runs before any project code. An unauthenticated request to `/mcp` is
refused before a tool is ever reached — a property covered directly by a test
using a canary tool.

The `/authorize` form asks for an Apple ID and an app-specific password. It
checks the address against a two-source allow list, proves the credential
against Apple with exactly **one** IMAP login, and only redirects to an
allowlisted origin.

Every refusal is held to a floor of about three seconds, counted from the first
statement of the request. That is deliberate: a wrong password, an address that
is not on the list, and a badly-shaped value all take the same time and give the
same message, so a stopwatch cannot tell them apart and cannot be used to learn
who is on the list.

Three limiter layers sit under that form:

| Layer | What it counts | Why |
|-------|----------------|-----|
| The time floor | Nothing — it holds every failing answer open for the same span | It needs no durable counter, so it still works when a store write fails |
| A per-source connection counter | Connections from one source over a one-minute window | Blunts a flood before it reaches the credential path |
| A per-person failure counter | Five failed attempts in an hour, keyed by the person | Stops a guessing run against one named address |

### Who can sign in

Two sources, asked in order:

1. **The seed** — the owner's own address, a config value, read on **every**
   request.
2. **The store** — a KV document, `allow-list:v1`, holding everyone else, read
   **only at sign-in**.

They are split because the two readers ask different questions. The per-request
door has to answer synchronously; a store read is an `await`. Keeping the
owner's own address in the config also means a bad store write can never lock
the owner out of their own server.

An **absent, empty or malformed** document means nobody beyond the seed. Never
everybody. The server refuses rather than guessing. Exactly one value opens it
to anyone, and that value is the literal `["*"]`.

### Removing someone, and what it costs

**It is two steps, and the second one is not optional.**

1. Take the address out of `allow-list:v1`. No deploy is needed; the store is
   read fresh at every sign-in, so the next one they attempt is refused.
2. Revoke their grants — `node scripts/grants.mjs revoke --address … --yes`.

Here is why step 1 alone is not enough, stated rather than left to be
discovered.

1. **The per-request door reads the seed only.** It cannot read the store,
   because a store read is an `await` and the door has a tested contract that it
   never awaits.
2. **So a well-shaped grant carrying an address the seed does not name is still
   served.** The grant is itself the evidence that a login passed the store
   check when it was minted.
3. **Therefore taking someone off the list ends their *next* sign-in.** It does
   not end the session they already have.
4. **Ending a live session needs the revoke.** Allow about a minute for the
   store to settle; the script re-lists after deleting and exits non-zero if
   anything is left.
5. **The honest sentence, and it belongs before the invitation rather than
   after:** when you add someone, you are handing out access that survives your
   removing them from the list, until you also revoke.

This is an accepted weakening, recorded here with its cost, because the
alternative — making the per-request door await a store read — is a change to
the one property that keeps the door cheap and testable.

### Where a credential lives

- Only in the grant's encrypted props, and — once decrypted for a request — in a
  `WeakMap` that is private to one module and keyed by the principal object
  itself. It dies with the principal.
- Credentials are consumed by write-only helpers that return nothing, so no
  object holding a password is ever built to be serialized.
- There are **no logging calls anywhere in `src/`**. IMAP's `LOGIN` carries the
  password inline in the command stream, so a single "log the command I'm
  sending" line would leak it — the rule is therefore absolute, and enforced by
  a scanner on every commit.
- Errors are mapped to a fixed, small vocabulary by dispatching on the error
  *type*. No error message echoes a caught value's text, and no diagnostic
  field repeats the last command sent.

### Per-user scoping

Every store key carries the user's own derived id, with nothing between the key
prefix and the id. That is enforced by a scan rule, not by care: a key with no
user segment is a key any signed-in caller could name.

So one person's cache, staging objects and counters cannot be reached through
another person's session.

### The dead-password pause

**What it is.** When Apple itself refuses the password saved in a grant, a
marker goes into the store for that person, and for fifteen minutes the server
refuses their calls before anything reaches Apple. Apple's own lockout
threshold is unpublished, and walking into it locks the person out of their own
mail in Mail.app on their own devices. A revoked or rotated app-specific
password would otherwise turn every tool call into a doomed login.

**What it is not.** It is not a lockout of this server, and it is not something
the sign-in page can start. The page never sets the marker — that asymmetry is
what stops a stranger who knows a listed address from pausing that person's
working apps.

**Two tools deliberately answer through it**: `mail_imap_diagnose` and
`dav_diagnose` (owner decision, 2026-09-22). The tool somebody runs to find out
*why* has to stay answerable while a pause is in force — including a pause it
started itself. `account_whoami` stays subject to the pause, and the exemption
is granted by an explicit registration rather than assumed.

A successful sign-in clears the marker, so someone who has just made a fresh
app-specific password does not wait out the fifteen minutes and conclude the fix
did not work.

### The assistant cannot send mail

There is no SMTP path and no mail-sending library. The assistant writes drafts
into the iCloud Drafts folder via IMAP `APPEND` and nothing else. A human
reviews every draft and sends it. This is the backstop against prompt-injected
content in an email reaching an outbound message under your name. The draft
write is built in exactly one module, enforced as a count (zero writers is as
much a violation as two).

### Reading mail does not change it

Every read opens its mailbox **read-only**, and every fetch uses the peeking
form, so the assistant reading your mail never sets the seen flag. Read status
stays a field *you* control. It changes only when you ask the assistant to mark
a message read or unread, one message at a time.

### Destructive calendar actions are gated

Creating an event with attendees, updating an event, and deleting an event all
**write nothing on the first call**. They return a preview plus a signed,
single-use, short-lived confirmation token. The change is applied only when
`calendar_commit` replays that token and the exact previewed change. The token
is HMAC-signed with `CONFIRM_SECRET`, carries a unique id spent once in KV, and
is bound to a hash of the change so it cannot be altered before commit. This
ensures you see *who* will be notified and *what* will change before anything
irreversible happens.

### Untrusted content is fenced

Mail bodies, event titles, contact fields, and calendar names are data from the
outside world. Tool results wrap them in an explicit untrusted-content fence
(a notice plus a nonce-delimited block) so the assistant is told to treat them
as content to report, never as instructions to follow. Attendee lists for any
write are always caller-supplied — never derived from content the server read.

### One connection per request

IMAP sessions are opened, used, and closed within a single request; there is no
connection pooling and no fan-out. This is enforced structurally (one socket
importer, one session orchestrator, no concurrent combinator around either) so
the server cannot exhaust iCloud's per-account connection ceiling and lock you
out of your own mail.

### No Zero Trust portal in front of this server

This server does not sit behind a Cloudflare Zero Trust MCP portal, and it is
not going to. That is a decision with a reason, not a gap nobody has got round
to yet.

The reason is one setting. Cloudflare's guidance for an unattended caller — a
service token — tells you to turn the portal's per-user authentication off. With
it off, every caller through the portal shares one identity: whichever account
authenticated the server first. This server is built on the opposite of that. A
separate Apple credential per person, a separate cache, separate counters, a
separate everything — and that one setting would collapse all of it. Nothing in
this repository could tell. It is account configuration, invisible to the test
suite, the commit scan and the pre-commit hook. A related step gets there by
another route: configuring this server's own OAuth provider as the access layer
is the documented remedy for a portal being bypassable by URL, and it replaces
this server's sign-in outright, ending per-user Apple grants.

So the constraints are written here as standing refusals, before any portal
exists. A future session reading the vendor's documentation will find the
recommended-but-wrong path; it should find these first.

- **Per-user authentication must be Enabled.** With it off there is one identity,
  and the multi-user model is gone.
- **No service token, ever**, and no autonomous caller routed through a portal.
- **No tool aliases and no description overrides.** Tool names here carry
  promises a model reasons from, and tool descriptions carry the
  untrusted-content warnings. A dashboard can rewrite both with no diff, no
  review and no commit-time scan.
- **A portal is never the gate.** The allow list is, and always was. Cloudflare's
  own documentation concedes that a user blocked by an access policy can still
  reach the server directly by its URL.

What would have to change for this to be worth revisiting is the identity model
itself. A portal is the right answer when it supplies something missing — when
the server behind it has no authentication of its own, or when every caller
legitimately is the same person. Neither is true here. It was not dropped for
cost: Zero Trust is already in use on this account and there is no per-seat
charge at this size. It was not dropped for difficulty: no code change was
needed. And it was not dropped because a trial failed — whether a portal's
sign-in composes with this server's own was never tested, and that question is
still open for anyone who revisits this.

## Scope for reports

**In scope:** authentication or authorization bypass; one person reaching
another person's account, cache, staged files or counters; credential exposure
in logs, responses, or errors; a path that sends mail or mutates data without
the preview/commit gate; a way to make the server mark mail read; injection that
escapes the untrusted-content fence into tool-calling behavior; the transport
safety rules being circumventable.

**Out of scope:** anything requiring your Cloudflare account or Apple
credentials to already be compromised; the deliberate design decisions above
(no sending, no background jobs, no Zero Trust portal in front of the endpoint,
and the two-step removal whose cost is stated above); and issues in third-party
dependencies that should be reported upstream
(tell us anyway if they affect this server).
