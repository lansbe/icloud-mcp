# Architecture

This document describes how iCloud MCP is built: the request lifecycle, the
transport layers, the safety model and how it is enforced, and how to work on
the code. For what the project is and how to deploy it, see
[README.md](README.md).

---

## Overview

iCloud MCP is one stateless Cloudflare Worker. Its default export is an OAuth
provider that owns all routing; authenticated MCP requests are dispatched to an
MCP handler that builds a fresh server per request and registers tools grouped
by service. Mail tools speak IMAP over a raw TLS socket; calendar and contact
tools speak CalDAV/CardDAV over HTTPS via `tsdav`. Nothing is held between
requests except OAuth records and a short-lived discovery cache, both in KV.

**Several people can sign in, each reaching only their own account.** Identity
is per person, not per deployment: each one signs in at `/authorize` with their
own Apple ID and their own Apple app-specific password, which is proved against
Apple once and then lives only inside that person's own encrypted grant. The
server holds no account credential of its own, and every store key carries the
person's derived id.

```
                         Cloudflare Worker (src/index.ts)
                                     │
                    OAuthProvider (owns routing, gates tokens)
                       │                              │
         apiRoute "/mcp"                     everything else
                       │                              │
             mcpApiHandler adapter              loginHandler
             (preserves ExecutionContext)       (/authorize, 404s)
                       │
             createMcpHandler(createServerFactory())
                       │
        ┌──────────────┼───────────────┬───────────────┐
     mail tools     calendar tools   contact tools   diagnostics
        │                │                │
   IMAP/TLS 993     CalDAV/HTTPS     CardDAV/HTTPS
```

---

## Request lifecycle

1. **Entry.** `src/index.ts` exports `new OAuthProvider<Env>(oauthProviderOptions)`.
   The provider is the Worker; no project code runs in front of the token check.

2. **OAuth options.** `src/auth/oauth.ts` defines the provider config as a named
   object (so tests can compose the real configuration and substitute only the
   API handler):
   - `apiRoute: "/mcp"`, `apiHandler: mcpApiHandler`, `defaultHandler: loginHandler`
   - `authorizeEndpoint: "/authorize"`, `tokenEndpoint: "/oauth/token"`,
     `clientRegistrationEndpoint: "/oauth/register"` (Dynamic Client
     Registration only)
   - `accessTokenTTL: 3600`, `refreshTokenTTL: 2592000`, `scopesSupported: ["mcp"]`
   - `resourceMetadata.resource = https://${DEPLOYED_HOSTNAME}/mcp` — the RFC 8707
     token audience. Changing the hostname after tokens are issued invalidates
     them.
   - `allowImplicitFlow: false`, `allowPlainPKCE: false`

3. **Authenticated dispatch.** A valid bearer token to `/mcp` is dispatched to
   `mcpApiHandler.fetch(request, env, ctx)` in `src/mcp/api-handler.ts`. This is
   an **explicit adapter**, not the raw handler: `createMcpHandler` returns a
   hybrid whose `.fetch` takes a per-request *options* object as its second
   argument, so assigning it directly would land `env` where options are
   expected and silently drop the `ExecutionContext` (and the OAuth-decrypted
   `ctx.props`). The adapter forwards all three arguments correctly.

4. **The MCP handler.** `createMcpHandler(createServerFactory(), { route: "/mcp",
   allowedHostnames: [DEPLOYED_HOSTNAME], allowedOriginHostnames:
   [DEPLOYED_HOSTNAME], legacy: "stateless" })`. Host and origin validation are
   passed explicitly because `workers_dev: false` removed the workers.dev host
   from which they would otherwise be derived — without them, validation is
   silently skipped on a custom domain. `legacy: "stateless"` serves the
   2025-era compatibility lane so a version-less `initialize` (as Claude
   Desktop's connector sends) is answered; this selection happens inside the
   authenticated boundary.

5. **Per-request server.** `createServerFactory()` (`src/mcp/server.ts`) runs
   once per request. It builds a fresh `McpServer`, a request-scoped session
   gate and DAV fetch, and registers the tool groups in order: diagnostics,
   mail, DAV-diagnostics, calendar, contacts.

6. **Non-API paths.** Everything that is not `/mcp` goes to `loginHandler`
   (`src/auth/login-handler.ts`): the `/authorize` consent form (constant-time
   secret compare, per-source brute-force counter in `OAUTH_KV`, redirect-origin
   allowlist) and a self-describing 404 for anything else.

---

## Module map

### Root (`src/`)

| File | Role |
|------|------|
| `index.ts` | Worker entry — the OAuth provider. |
| `env.ts` | The binding surface: declares `Cloudflare.Env` (KV, R2, vars, secrets). |
| `errors.ts` | Closed error vocabulary and the single translation boundary (`toErrorCategory`). |
| `tokens.ts` | Byte-level token codec (base64url, strict UTF-8) shared by every opaque-id and cursor. |
| `confirm.ts` | The calendar-write confirmation capability (signed, single-use, short-lived). |
| `deployed-hostname.generated.ts` | **Generated, git-ignored** — the hostname baked in from config. |

### `auth/` — OAuth gating

| File | Role |
|------|------|
| `oauth.ts` | The `OAuthProviderOptions` object. |
| `login-handler.ts` | The `/authorize` surface: consent, the Apple ID and app-password form, the two-source allow-list check, the refusal floor and limiter layers, redirect allowlist. |
| `allow-list.ts` | The one store read, the parse rule shared with the seed, and what an absent or malformed document means. |

### `mcp/` — protocol layer

| File | Role |
|------|------|
| `api-handler.ts` | MCP termination via `createMcpHandler`; the `mcpApiHandler` adapter; host/origin config. |
| `server.ts` | Per-request server factory; session gate + DAV fetch; all tool registrations. |
| `untrusted.ts` | The untrusted-content fence (notice + nonce + trusted/untrusted split). |
| `tools/diagnose.ts` | `mail_imap_diagnose`. |
| `tools/mail.ts` | The 10 mail tools and their response shapers. |
| `tools/dav-diagnose.ts` | `dav_diagnose`. |
| `tools/calendar.ts` | The 9 calendar tools; preview/commit logic. |
| `tools/contacts.ts` | The 2 contact tools. |

### `mail/` — IMAP

| File | Role |
|------|------|
| `socket.ts` | **The only module that may open a TCP socket.** `connectImap()` takes no parameters. |
| `service.ts` | **The one session orchestrator** (`withMailSession`, `withMailSessionOver`, `createSessionGate`); the sole draft-write (`APPEND`) site. |
| `imap-session.ts` | The IMAP wire conversation over a `DuplexLike` (socket-free, no logging). |
| `imap-parser.ts` | Pure IMAP line parsing, no I/O. |
| `mime.ts` | Raw RFC822 → decoded message (`postal-mime`, `HTMLRewriter`). |
| `compose.ts` | Message fields → RFC 5322 bytes (hand-rolled). |
| `credentials.ts` | Write-only credential helpers (consume the password, return nothing). |
| `extract.ts` | Attachment bytes → text (`unpdf` for PDFs). |
| `ids.ts` | Opaque identifiers for messages/folders/attachments/pages. |
| `diagnose.ts` | The connectivity proof: one socket, report, close. |

### `dav/` — CalDAV/CardDAV

| File | Role |
|------|------|
| `transport.ts` | **The only module that may issue a DAV request.** Builds `davFetch` (per-call Basic auth, manual redirects, status classification, per-request serialization). |
| `discovery.ts` | **The only module that may name an iCloud DAV hostname.** Discovery + `DAV_CACHE` (24 h TTL). |
| `calendar.ts` | Calendar service: collections, bounded range expansion, keyset paging, write helpers. |
| `contacts.ts` | Contacts service: address books, matching, paging. |
| `icalendar.ts` | Pure iCalendar parsing, timezones, recurrence expansion (`ical.js`). |
| `vcard.ts` | Pure vCard parsing/field extraction (via `ical.js`). |
| `ids.ts` | Opaque identifiers (collection URL + object URL in one token). |
| `errors.ts` | DAV typed errors + translation boundary (shares only the vocabulary with `errors.ts`). |
| `diagnose.ts` | Transport-free half of `dav_diagnose`. |

### `staging/` and `feed/`

| File | Role |
|------|------|
| `staging/r2.ts` | The staging bucket: put/get/delete outside the mail session. |
| `staging/presign.ts` | Presigned uploads (`aws4fetch`); the only reader of the two R2 credentials. |
| `feed/subscription-feed.ts` | **The only module that may fetch a subscription feed.** Attaches no credential (the feed host is a third party). |

---

## Transport

### IMAP: one connection per request

- **`socket.ts`** is the sole importer of `cloudflare:sockets`. `connectImap()`
  takes no parameters — host (`imap.mail.me.com`), port (`993`), and transport
  (`secureTransport: "on"`, implicit TLS) are literals at the `connect()` call.
  There is no value a caller can pass that reaches the socket. `MAX_CONCURRENT_CONNECTIONS = 3`
  documents the ceiling; it does not enforce it.
- **`service.ts`** holds the one orchestrator. `createSessionGate()` returns a
  gate whose `acquire()` throws if already held. `withMailSessionOver()` calls
  `gate.acquire()` before its `try`, with no `await` ahead of it, so a refused
  second caller can neither release the first caller's slot nor interleave into
  it. `withMailSession()` checks the gate, opens a socket, and delegates.
- **Flow:** connect → `LOGIN` → `EXAMINE` (read-only) → work → `LOGOUT` → close,
  every call. Decoding, extraction, and storage all happen *outside* the
  session.

Why one connection: production allows six platform connections per Worker
invocation, shared across KV, outbound fetch, and sockets — one already spent by
the OAuth provider. iCloud's own per-account ceiling is lower and undocumented,
and exhausting it locks you out of your own mail in Mail.app. So a multi-mailbox
operation is serial by construction, never a fan-out.

### CalDAV/CardDAV: one fetch choke-point

- **`transport.ts`** builds `davFetch`, the sole `fetch()` caller under `dav/`.
  It concentrates four obligations: per-call Basic auth (built and discarded,
  never held); `redirect: "manual"` (so a credential is never forwarded to a
  redirect and a stale-shard 3xx is observable); status-number classification
  (`tsdav` returns `ok: false` rather than throwing); and a per-request
  serialization gate that queues rather than refuses.
- **`discovery.ts`** is the sole namer of iCloud DAV hostnames
  (`caldav.icloud.com`, `contacts.icloud.com`), used only for the first
  discovery `PROPFIND`. Resolved, sharded home URLs are cached in `DAV_CACHE`
  under `dav:v1:<hash>:<service>` for 24 hours. Only discovery metadata is
  cached — never event or contact content. `dav_diagnose` with `refresh: true`
  clears these keys.

### Attachment staging (R2)

Staging a file for a draft happens outside the IMAP session. `staging/r2.ts`
writes bytes under a `staging/` prefix in the `ATTACHMENT_STAGING` bucket, with a
one-day lifecycle rule (created out of band). `staging/presign.ts` mints
presigned upload URLs with `aws4fetch` and is the only reader of the R2 S3
credentials. The staging token expires at exactly 24 h; the bytes live 24–48 h,
so the token always dies before the bytes it names.

---

## The confirmation capability

Destructive or notifying calendar operations —
`calendar_update_event`, `calendar_delete_event`, and `calendar_create_event`
**with attendees** — write nothing on the first call. They return an
`EventPreview` (what would change, and who would be told) plus a signed
`confirmToken` and a `change` object. `calendar_commit` replays both, unaltered,
to apply the change.

`src/confirm.ts` implements the token:

- Sealed with HMAC-SHA-256 over `CONFIRM_SECRET`, imported once as a
  non-extractable `CryptoKey`. It fails closed on both mint and verify if the
  secret is absent.
- Carries a `jti` (`crypto.randomUUID()`) spent once by writing
  `confirm:v1:<jti>` to `CONFIRM_KV`, and a canonical hash of the change so any
  alteration to `change` before commit is refused.
- Lifetime `CONFIRM_TTL_SECONDS = 300`.
- KV's eventual consistency is backstopped by an `If-Match` ETag precondition on
  the DAV write, which returns 412 on a race.

`CONFIRM_SECRET` exists only to sign and verify these tokens, and it is kept to
that one job. Rotating it invalidates every token in flight and nothing else —
no sign-in breaks, no stored credential is touched. A key that also did
something else could not be rotated that cheaply.

---

## Cross-cutting concerns

### Untrusted content

`src/mcp/untrusted.ts` sits above both protocol trees. Tool results that carry
outside data — mail bodies, event titles, contact fields, calendar names — are
wrapped in a fence: a preamble telling the model this is data to report, a
nonce, and a two-block trusted/untrusted split. Attendee lists for any write are
always caller-supplied and never derived from content the server read.

### Identifiers

Every id the assistant sees is opaque. Mail ids carry mailbox + `UIDVALIDITY` +
`UID` together; DAV ids carry the collection URL and object URL together. This
means an id is self-contained and cannot be pointed at the wrong resource by
editing a fragment of it. Cursors for paging use the same codec (`src/tokens.ts`).

### Errors

`src/errors.ts` maps every failure to a small fixed vocabulary by dispatching on
the error *type*, never by reading a caught value's `.message` or `.stack`. DAV
errors have their own typed classes (`src/dav/errors.ts`) that share only the
vocabulary. No error text echoes a credential or a command.

---

## Safety model

Five rules are safety boundaries, not style. Each is enforced by
`scripts/forbidden-tokens.mjs`. Full reasoning lives in `.claude/CLAUDE.md`;
this is the summary.

1. **Banned transport paths.** `startTls()`, the opportunistic-TLS transport
   mode, and port 143 must never appear. Implicit TLS on 993 covers every need;
   the opportunistic path is the least reliable part of the socket API.

2. **No mail sending, ever.** SMTP ports (25/465/587) and mail-sending libraries
   are banned. The draft `APPEND` is the entire write path, built in exactly one
   module (`src/mail/service.ts`) — enforced as a *count*, so zero writers is as
   much a violation as two. The human review step is the backstop against
   prompt-injected content going out. (Calendar invitations are reconciled
   separately: the send is iCloud's, attendees are caller-supplied, and any
   create with attendees is gated by preview/commit.)

3. **One socket importer.** `cloudflare:sockets` is imported by exactly one file.
   `connectImap()` takes no parameters, so the forbidden state is unspeakable.
   The one-connection property is defended again one layer up: one session
   orchestrator, and no concurrent combinator around it or the socket open.

4. **Credentials never reach a log or an error.** There are no logging calls
   anywhere in `src/`. IMAP `LOGIN` carries the password inline, so there is no
   field a redactor could target — the rule has to be absolute. A log call
   naming the `env` object or a secret binding is banned in `scripts/` and
   `test/` too.

5. **Reading mail does not mark it read.** Mailboxes are opened read-only
   (`EXAMINE`), and every fetch uses the peeking form. Non-peeking fetch items
   are banned.

### Enforcement

`scripts/forbidden-tokens.mjs` is a single list of regex rules (each with a
reason printed on rejection) plus count constraints:

- **Pattern rules** cover the five conventions above, plus DAV-specific ones
  (no concurrent DAV requests, no eager loading, choke-point ownership for the
  DAV host, DAV fetch, and the subscription feed).
- **Count constraints** (`checkSocketOwnership`, `checkDavHostOwnership`,
  `checkDavFetchOwnership`, `checkAppendOwnership`, `checkSubscriptionFeedFetchOwnership`)
  fail in **both** directions — a duplicated owner *and* a missing one.
- `scanWranglerConfig` rejects the non-existent `limits.simultaneousConnections`
  key (silently accepted by `wrangler deploy --dry-run`) and any deployed
  hostname hardcoded back into `src/` instead of derived from config.
- `checkCommitHook` verifies the pre-commit hook exists, is executable, and
  still runs the scan.

It runs from **two** gates: the test suite (`test/forbidden-tokens.test.ts`) and
`.husky/pre-commit`. The test asserts set-equality of rule ids against
known-violating samples in both directions, so a rule that matches nothing is
indistinguishable from one that was never added — and fails the suite.

**Do not weaken a rule to make a commit pass.** Exclusion is by path, never by
making a rule see less. If a rule is genuinely in the way, that is a decision
about the safety boundary — raise it.

---

## Configuration and the generated hostname

The deployed hostname has one source of truth: `routes[0].pattern` in the
wrangler config.

- `scripts/hostname.mjs` reads it (falling back to `wrangler.jsonc.example` on a
  fresh clone that has no real config yet).
- `scripts/write-hostname.mjs` bakes it into the git-ignored
  `src/deployed-hostname.generated.ts`, so module-init code can import it — a
  deployed Worker has no filesystem and cannot read the config at runtime. It
  runs on `prepare`, `pretest`, `pretypecheck`, and `predeploy`, and copies
  `wrangler.jsonc.example` → `wrangler.jsonc` if the real config is missing.
- `src/mcp/api-handler.ts` re-exports the generated constant. A hardcoded
  hostname literal reappearing there fails the scan (`hostname-hardcoded`).

The tracked config is `wrangler.jsonc.example` (all placeholders). The real
`wrangler.jsonc`, holding your account id, KV ids, and domain, is git-ignored.

---

## Development

### Setup

```bash
npm install            # installs deps, copies the config template, generates the hostname
cp .dev.vars.example .dev.vars   # then fill in local secrets
npx wrangler dev       # run locally against Miniflare
```

### The gates

```bash
npm run typecheck   # tsc --noEmit
npm run scan        # the safety scanner
npm test            # ~2,400 tests inside real workerd
```

Tests run under [`@cloudflare/vitest-pool-workers`](https://developers.cloudflare.com/workers/testing/vitest-integration/)
in two projects: a small `static` project (Node env) for
`test/forbidden-tokens.test.ts`, which reads the repo tree off disk, and a
`workers` project (real `workerd`) for everything else. Secrets and config are
faked in `vitest.config.ts` (`*-not-real`). **No test authenticates to a real
Apple ID** — that is a hard rule (D-09). Never point an automated step at a real
account.

### Commits

The pre-commit hook runs the scanner and refuses a staged `.dev.vars`. Keep
commits focused; the scanner runs on every one.

### Changing safety-critical code

Before touching `src/mail/socket.ts`, `src/mail/service.ts`, `src/dav/transport.ts`,
`src/dav/discovery.ts`, the confirmation flow, or the OAuth/host-validation
setup, read the *Safety model* above and the extended rationale in
`.claude/CLAUDE.md`. These modules carry guarantees that the scanner enforces
but cannot fully explain — the reasons matter.

---

## Non-goals and deliberate boundaries

- **No SMTP / sending.** A safety boundary (see rule 2).
- **No autonomous behavior.** No cron, no watchers, no digests. Proactive work
  belongs in a separate, stateful project.
- **No other iCloud services.** No Reminders, Notes, or Photos.
- **No local content cache.** iCloud is the system of record; only discovery
  metadata is cached, for 24 hours.
- **No IMAP connection pooling.** Connect, act, close — every call.
