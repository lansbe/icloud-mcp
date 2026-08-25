# Security Policy

iCloud MCP reaches a real personal iCloud account — mail, calendar, and
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

The only true secrets are stored in **Cloudflare Secrets** and are never in the
repository, never logged, and never returned in any response:

- `AUTH_SECRET` — the login secret for the `/authorize` form.
- `APPLE_ID` — the account's Apple ID.
- `APPLE_APP_PASSWORD` — the Apple app-specific password.
- `CONFIRM_SECRET` — the HMAC key for calendar confirmation tokens.
- `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` — the R2 S3 API token for
  presigned attachment uploads.

The following are **not** secrets — they are opaque handles that grant nothing
on their own, and they live in configuration:

- The Cloudflare account id (`R2_ACCOUNT_ID`).
- KV namespace ids and the R2 bucket name.
- The deployed hostname.

In the public repository these config values are placeholders; the real ones
live only in your git-ignored `wrangler.jsonc`.

## The security model

### The endpoint is authenticated

The Worker's entry point *is* the OAuth provider
(`@cloudflare/workers-oauth-provider`). It owns routing, so the bearer-token
check runs before any project code. An unauthenticated request to `/mcp` is
refused before a tool is ever reached — a property covered directly by a test
using a canary tool. The `/authorize` form compares the submitted secret to
`AUTH_SECRET` in constant time, rate-limits by source, and only redirects to an
allowlisted origin.

### Credentials never leave the server

- Apple credentials are consumed by write-only helpers that return nothing, so
  no object holding the password is ever built to be serialized.
- There are **no logging calls anywhere in `src/`**. IMAP's `LOGIN` carries the
  password inline in the command stream, so a single "log the command I'm
  sending" line would leak it — the rule is therefore absolute, and enforced by
  a scanner on every commit.
- Errors are mapped to a fixed, small vocabulary by dispatching on the error
  *type*. No error message echoes a caught value's text, and no diagnostic
  field repeats the last command sent.

### The assistant cannot send mail

There is no SMTP path and no mail-sending library. The assistant writes drafts
into the iCloud Drafts folder via IMAP `APPEND` and nothing else. A human
reviews every draft and sends it. This is the backstop against prompt-injected
content in an email reaching an outbound message under your name. The draft
write is built in exactly one module, enforced as a count (zero writers is as
much a violation as two).

### Reading mail does not change it

Mailboxes are opened **read-only**, and every fetch uses the peeking form, so
the assistant reading your mail never sets the seen flag. Read status stays a
field *you* control.

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

## Scope for reports

**In scope:** authentication or authorization bypass; credential exposure in
logs, responses, or errors; a path that sends mail or mutates data without the
preview/commit gate; a way to make the server mark mail read; injection that
escapes the untrusted-content fence into tool-calling behavior; the transport
safety rules being circumventable.

**Out of scope:** anything requiring your Cloudflare account or Apple
credentials to already be compromised; the deliberate design decisions above
(no multi-user, no sending, no background jobs); and issues in third-party
dependencies that should be reported upstream (tell us anyway if they affect
this server).
