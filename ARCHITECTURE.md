# Architecture

This document describes how iCloud MCP is built: the request lifecycle, the
per-person Durable Object, the transport layers, recall, the rules job, the
safety model and how it is enforced, and how to work on the code. For what the
project is and how to deploy it, see [README.md](README.md).

---

## Overview

iCloud MCP is one Cloudflare Worker and one Durable Object class. The Worker's
default export is an OAuth provider that owns all routing. Authenticated MCP
requests go through a door that checks the grant, then to an MCP handler that
builds a fresh server per request and registers the tools. Mail tools speak
IMAP over a raw TLS socket. Calendar and contact tools speak CalDAV/CardDAV over
HTTPS through `tsdav`.

**Several people can sign in, each reaching only their own account.** Each one
signs in at `/authorize` with their own Apple ID and their own Apple
app-specific password. The password is proved against Apple once, then lives
only inside that person's encrypted grant. The server holds no account
credential of its own, and every store key carries the person's derived id.

**Each person has one Durable Object**, the `UserAgent`. It holds their
connection lease, their recall ledger, their sealed autonomy key, their rules
and one alarm. It never opens a socket and never imports mail, DAV, tool or
auth code. When it needs mail, it calls this Worker's own `/mcp` through the
`SELF` binding, like any other client.

```
                         Cloudflare Worker (src/index.ts)
                                     │
                    OAuthProvider (owns routing, gates tokens)
                       │                              │
         apiRoute "/mcp"                     everything else
                       │                              │
            the door (api-handler.ts)     /save/<link> → save route
            grant + allow list +          other paths  → loginHandler
            principal + pause check                      (/authorize, 404s)
                       │
             createMcpHandler(createServerFactory(...))
                       │
     ┌─────────┬───────┴──────┬──────────────┬──────────────┬─────────┐
  mail tools  recall      calendar tools  contact tools   rules    diagnostics
     │     (+ recall step)      │              │         tools
     │                          │              │
  lease in the person's    CalDAV/HTTPS   CardDAV/HTTPS
  UserAgent, then
  IMAP/TLS 993

  UserAgent (one per person): lease, recall ledger, autonomy key, rules, alarm
     alarm → rules job → SELF binding → this Worker's /mcp (same door)
```

---

## Request lifecycle

1. **Entry.** `src/index.ts` exports `new OAuthProvider<Env>(oauthProviderOptions)`
   as the Worker, and exports the `UserAgent` class. The provider is the
   Worker; no project code runs in front of the token check.

2. **OAuth options.** `src/auth/oauth.ts` defines the provider config as a named
   object, so tests can compose the real configuration and swap only the API
   handler:
   - `apiRoute: "/mcp"`, `apiHandler: mcpApiHandler`. The default handler sends
     `/save/…` to the download route and everything else to `loginHandler`.
   - `authorizeEndpoint: "/authorize"`, `tokenEndpoint: "/oauth/token"`,
     `clientRegistrationEndpoint: "/oauth/register"` (Dynamic Client
     Registration only), with a callback that refuses junk redirect URIs at
     registration.
   - `accessTokenTTL: 3600`. `refreshTokenTTL` and `clientRegistrationTTL` are
     present and set to `undefined`, so a sign-in lasts until someone revokes
     it. Deleting either line brings back the library's 30- or 90-day default.
   - `scopesSupported: ["mcp"]`.
   - `resourceMetadata.resource = https://${DEPLOYED_HOSTNAME}/mcp`, the RFC 8707
     token audience. Changing the hostname after tokens are issued invalidates
     them.
   - `allowImplicitFlow: false`, `allowPlainPKCE: false`.

3. **The door.** A valid bearer token to `/mcp` reaches
   `mcpApiHandler.fetch(request, env, ctx)` in `src/mcp/api-handler.ts`. It:
   - refuses a grant whose props are not exactly the expected shape, and
     refuses everyone when the allow-list seed parses as nobody (a 401 that
     asks the client to sign in again). It does not look the address up in the
     list, so taking someone off the list also means revoking their grants
     (README says how);
   - builds the principal from the grant's props: the user id and the Apple ID,
     with the password kept in a holder private to `src/principal.ts`;
   - wraps it in the dead-password pause check (`src/password-pause.ts`);
   - builds a reader for which client the grant belongs to, used only by recall
     and the save tool to refuse the autonomy key.

   It is an explicit adapter, not the raw handler. `createMcpHandler` returns a
   hybrid whose `.fetch` takes an options object as its second argument, so
   assigning it directly would put `env` where options go and drop the
   `ExecutionContext` and `ctx.props`.

4. **The MCP handler.** `createMcpHandler(createServerFactory(...), { route:
   "/mcp", allowedHostnames: [DEPLOYED_HOSTNAME], allowedOriginHostnames:
   [DEPLOYED_HOSTNAME], legacy: "stateless" })`. Host and origin checks are
   passed explicitly because `workers_dev: false` removed the workers.dev host
   they would otherwise come from. Without them, the checks are skipped on a
   custom domain. `legacy: "stateless"` answers a version-less `initialize`
   (as Claude Desktop's connector sends), inside the authenticated boundary.

5. **Per-request server.** `createServerFactory()` (`src/mcp/server.ts`) runs
   once per request. It builds a fresh `McpServer` with the server
   instructions, a request-scoped session gate, the leased mail runner over
   that gate, a DAV fetch, and the recall step seam. It then registers the
   tools: the IMAP diagnostic, the account answer, the mail, recall and change
   tools (through the recall step seam), the recall backfill, the DAV
   diagnostic, calendar, contacts, rules and save.

6. **A mail tool call.** The tool takes the person's lease in their
   `UserAgent` before it opens an iCloud connection, and gives it back after
   the connection closes. A second call for the same person while the lease is
   held is refused at once, not queued.

7. **The recall step.** After a mail, recall or change tool answers without an
   error, one recall build step runs for that person, and then the same
   answer goes back. The step takes the lease itself, after the tool's session
   has closed. It is silent: a refusal or failure never reaches the answer.

8. **Non-API paths.** `/save/<link>` serves one saved attachment copy, with no
   sign-in (see *Saving attachments*). Everything else goes to `loginHandler`
   (`src/auth/login-handler.ts`): the `/authorize` sign-in page, and a
   self-describing 404.

9. **Sign-in.** At `/authorize` the person enters their Apple ID and
   app-specific password. The handler checks the allow list (the seed var and
   the `ALLOW_LIST_KV` store), applies the refusal floor and the two login
   rate limiters, checks the redirect URI, and proves the password against
   Apple. Only then does it complete the grant. After that it arms the
   person's autonomy key (see *The rules job*). If arming fails, the sign-in
   still succeeds.

---

## Module map

Every file under `src/` has one row here. `test/architecture-map.test.ts` fails
when a file is added or removed and this map does not follow. Each table's rows
are written relative to the directory in its heading.

### Root (`src/`)

| File | Role |
|------|------|
| `index.ts` | Worker entry. The default export is the OAuth provider; it also exports the `UserAgent` Durable Object class. |
| `env.ts` | The binding surface: declares `Cloudflare.Env` (KV, R2, the vector index, AI, the Durable Object, the self-binding, rate limiters, vars, secrets). |
| `errors.ts` | Closed error vocabulary and the single translation boundary (`toErrorCategory`). |
| `tokens.ts` | Byte-level token codec (base64url, strict UTF-8) shared by every opaque id and cursor. |
| `confirm.ts` | The confirmation capability behind every preview and commit: signed, single-use, short-lived. |
| `change-marker.ts` | The change check's marker: sealed, carried by the caller, never stored here. |
| `principal.ts` | Who a request acts for: the user id derived from an Apple ID, the principal, and the holder that keeps the password off it. Also `maskAppleId`. |
| `password-pause.ts` | The dead-password pause: after Apple refuses a stored password, stop asking Apple for that person for 15 minutes. |
| `configured-secret.ts` | The one "is this secret set" predicate every secret reader shares. |
| `deployed-hostname.generated.ts` | **Generated, git-ignored.** The hostname baked in from the wrangler config. |

### Sign-in (`auth/`)

| File | Role |
|------|------|
| `oauth.ts` | The `OAuthProviderOptions` object. Routes `/save/` to the download route and everything else to the login handler. |
| `login-handler.ts` | The `/authorize` flow: the allow-list check, the refusal floor and limiter layers, proving the password against Apple, the redirect allowlist, and arming the autonomy key after a sign-in. |
| `login-page.ts` | Every byte of the sign-in page a person sees. |
| `allow-list.ts` | The one store read, the parse rule shared with the seed, and what an absent or malformed document means. |

### Protocol layer (`mcp/`)

| File | Role |
|------|------|
| `api-handler.ts` | The door. Checks the grant against the allow list, builds the principal, and hands the request to `createMcpHandler`. Holds the host and origin config. |
| `server.ts` | The per-request server factory: the session gate, the leased mail runner, the DAV fetch, the recall step seam, and every tool registration. |
| `instructions.ts` | The server-level instructions a client shows the model with the tool list. |
| `grant-client.ts` | Reads which client a request's grant belongs to, so recall and the save tool can refuse the autonomy key. |
| `untrusted.ts` | The untrusted-content fence (notice, nonce, trusted/untrusted split). |

### Tool registrars (`mcp/tools/`)

Which group each file registers into. README's generated tool table lists every
tool; this map does not repeat it.

| File | Role |
|------|------|
| `diagnose.ts` | Diagnostics: the IMAP connectivity check. |
| `dav-diagnose.ts` | Diagnostics: the CalDAV/CardDAV discovery check, plus two shapers the DAV tools share. |
| `account.ts` | Diagnostics: which Apple ID this connection is signed in as. |
| `mail.ts` | Mail: listing, finding, reading, attachments, compose into Drafts, staging, read status, the flag, moves and the draft delete with their commit. |
| `recall.ts` | Mail: recall by meaning, and the recall backfill. |
| `save.ts` | Mail: saving attachments to the person's own computer, as one link each. |
| `changes.ts` | Changes: what changed in mail and calendars since a marker. |
| `calendar.ts` | Calendar: calendars, events, invitations, free slots, and the calendar commit. |
| `contacts.ts` | Contacts: the reads. It also calls the write registrar below. |
| `contacts-write.ts` | Contacts: create and update previews, and the contact commit. |
| `rules.ts` | Rules: list, add with a preview, commit, remove, and test a rule. |

### IMAP (`mail/`)

| File | Role |
|------|------|
| `socket.ts` | **The only module that may open a TCP socket.** `connectImap()` takes no parameters. |
| `service.ts` | **The two session orchestrators** over one private core: read (`withMailSession`, `withMailSessionOver`) and mutating (`withMutatingMailbox`, `withMutatingMailboxOver`), plus `createSessionGate`. The sole draft-write site, and the one place a mailbox is opened in the mutating form. |
| `triage.ts` | **The only user of the mutating orchestrator.** Hands out verbs, never a session: mark one message read or unread, flag or unflag one message, move a list of messages (a copy, then the removal of that one original), and move one draft to Trash. Fetches no message body. |
| `imap-session.ts` | The IMAP wire conversation over a `DuplexLike` (socket-free, no logging). |
| `imap-parser.ts` | Pure IMAP line parsing, no I/O. |
| `mime.ts` | Raw RFC822 → decoded message (`postal-mime`, `HTMLRewriter`). |
| `stream-decode.ts` | Turns a saved attachment's transfer-encoded windows back into its bytes, and refuses rather than return bytes it is not sure of. |
| `compose.ts` | Message fields → RFC 5322 bytes (hand-rolled). |
| `credentials.ts` | Write-only credential helpers (consume the password, return nothing). |
| `extract.ts` | Attachment bytes → text (`unpdf` for PDFs). |
| `ids.ts` | Opaque identifiers for messages, folders, attachments and pages. |
| `diagnose.ts` | The connectivity proof: one socket, report, close. |

### CalDAV/CardDAV (`dav/`)

| File | Role |
|------|------|
| `transport.ts` | **The only module that may issue a DAV request.** Builds `davFetch` (per-call Basic auth, manual redirects, status classification, per-request serialization). |
| `discovery.ts` | **The only module that may name an iCloud DAV hostname.** Discovery + `DAV_CACHE` (24 h TTL). |
| `calendar.ts` | Calendar service: collections, bounded range expansion, keyset paging, write helpers. |
| `contacts.ts` | Contacts service: address books, matching, paging, write helpers. |
| `icalendar.ts` | Pure iCalendar parsing, timezones, recurrence expansion (`ical.js`). |
| `vcard.ts` | Pure vCard parsing and field extraction (via `ical.js`). |
| `ids.ts` | Opaque identifiers (collection URL + object URL in one token). |
| `errors.ts` | DAV typed errors + translation boundary (shares only the vocabulary with `errors.ts`). |
| `diagnose.ts` | Transport-free half of `dav_diagnose`. |

### The per-person object and the rules job (`agent/`)

| File | Role |
|------|------|
| `user-agent.ts` | **The per-person Durable Object.** Holds the lease, its own stored name, the recall ledger, the sealed autonomy record, the rules and their job state, and one alarm. Never opens a socket, never imports mail, DAV, tool or auth code. |
| `lease.ts` | The connection lease as the Worker request sees it: `agentFor` (the only place a stub is built) and `createLeasedMail`, which takes the lease before a mail session and gives it back after. |
| `recall-ledger.ts` | The recall ledger's SQLite tables: every vector id a person owns, always a superset of the index. Also the page slot, pace and quota. |
| `autonomy.ts` | The autonomy key: exchange the code, seal the refresh token, the standing check, the alarm job, and disarm. |
| `autonomy-client.ts` | The autonomy client's fixed facts: its id, name, redirect path, and `AUTONOMY_TOOLS`, the four tools the job may name. |
| `autonomy-grants.ts` | The one place autonomy asks the OAuth library about grants: sweep old autonomy grants, and whether the key still stands. |
| `job.ts` | The rules job: one run from the alarm. Asks the change check for new inbox mail, matches, acts, records. |
| `cadence.ts` | The job's clock: one fixed interval, and a per-person offset. |
| `rules.ts` | A rule's shape, limits and the one strict parser. |
| `evaluate.ts` | The matcher: rule index, message index, flag or draft. No identifier leaves it. |
| `actions.ts` | The job's two actions: set the flag, and place a draft reply. |
| `recipient.ts` | The one place an address from a message becomes a recipient: the From address only. |
| `activity.ts` | The ring of the last 100 things the job did, with no subject, address or text. |
| `status.ts` | The small per-person status record the owner's grants script can read. |
| `tool-call.ts` | Types only: the shapes the job passes around. |
| `tool-reply.ts` | Reads the tools' answers inside the object, including the fenced part, strictly. |

### Recall (`recall/`)

| File | Role |
|------|------|
| `index.ts` | **The only module that may name the vector index binding.** Every read and write takes the principal and sets the namespace and filter from it. |
| `embed.ts` | **The only reader of the AI binding, and the one model id.** Text → vectors. |
| `ids.ts` | A vector's id: a digest of the user id and the message token. |
| `retention.ts` | The terms: 90-day retention, snippet and text caps, vector and page limits. |
| `pipeline.ts` | Index a batch (ledger first, store second) and recall from the person's own vectors. |
| `build.ts` | The build engine: one page per call, and the clean-up at sync time. |
| `mail-source.ts` | The real page source over IMAP: read-only, peeking, newest first. |
| `sync.ts` | One recall build step, and the backfill. Nothing else calls these. |
| `drive.ts` | **The one driver.** `withRecallStep` runs one step after a mail tool answers without an error; also runs the backfill. |
| `dead-ref.ts` | Removes a recall result that no longer opens. |
| `lifecycle.ts` | Expiry and the wholesale destroy, run from the object's alarm. |
| `grant-check.ts` | Asks whether this person still holds any grant. Only a definite "none" destroys their index. |

### Saving attachments (`save/`)

| File | Role |
|------|------|
| `stage.ts` | After the save tool's read-only session closes: decode each part, store a copy under the person's prefix, seal a link. |
| `link.ts` | Save links: sealed, self-validating, spent once. |
| `route.ts` | `GET /save/<link>`: serves one saved copy. No sign-in, no mail connection, no lease. |
| `filename.ts` | The suggested filename, safe to put in a shell command. |

### Attachment staging (`staging/`)

| File | Role |
|------|------|
| `r2.ts` | The staging bucket: put, get and delete, always outside the mail session. |
| `presign.ts` | Presigned uploads (`aws4fetch`); the only reader of the two R2 credentials. |

### Subscription feeds (`feed/`)

| File | Role |
|------|------|
| `subscription-feed.ts` | **The only module that may fetch a subscription feed.** Attaches no credential (the feed host is a third party). |

---

## Transport

### IMAP: one connection at a time

- **`socket.ts`** is the sole importer of `cloudflare:sockets`. `connectImap()`
  takes no parameters. Host (`imap.mail.me.com`), port (`993`) and transport
  (`secureTransport: "on"`, implicit TLS) are literals at the `connect()` call.
  No value a caller passes can reach the socket. `MAX_CONCURRENT_CONNECTIONS = 3`
  documents the ceiling; it does not enforce it.
- **`service.ts`** holds two orchestrators, read and mutating, over one private
  core. `createSessionGate()` returns a gate whose `acquire()` throws if a
  session is already open. Both kinds share it, so a request has at most one
  session open at a time, whichever kind. The core calls `gate.acquire()`
  before its `try`, with no `await` ahead of it, so a refused second caller can
  neither release the first caller's slot nor slip in beside it.
- **Sessions one after another are allowed.** A request can hold several
  sessions in turn, never together: a mail tool's own, then the sessions of
  the one recall step that may follow it. A backfill call's pages open their
  sessions the same way, one after another.
- **The lease, across requests.** The gate sees one request only. So before a
  mail tool opens a connection, it takes the lease in the person's `UserAgent`
  (`src/agent/lease.ts`). A second call for the same person that finds the
  lease held is refused at once with a plain reason. It is not queued. The
  lease expires on its own after 30 seconds, so a request that dies part-way
  cannot hold it for ever. The lease is added to the gate and does not replace
  it.
- **Flow:** connect → `LOGIN` → `EXAMINE` (read-only) → work → `LOGOUT` → close,
  for every session that opens a mailbox. The sign-in check, the folder listing
  and the drafts write open none. The one exception is `triage.ts`: it opens
  its mailbox in the mutating form, refuses unless iCloud says the mailbox is
  writable, then changes one flag or moves the messages it was given, one at a
  time. Decoding, extraction and storage all happen *outside* the session.

Why: production allows six platform connections per Worker invocation, shared
across KV, outbound fetch and sockets, and the OAuth provider has already spent
one. iCloud's own per-account ceiling is lower and undocumented, and running
into it locks the person out of their own mail in Mail.app. So a multi-mailbox
operation is serial, never a fan-out.

### CalDAV/CardDAV: one fetch choke-point

- **`transport.ts`** builds `davFetch`, the sole `fetch()` caller under `dav/`.
  It does four jobs: per-call Basic auth (built and thrown away, never held);
  `redirect: "manual"` (so a credential is never sent on to a redirect and a
  stale-shard 3xx can be seen); classifying the status number (`tsdav` returns
  `ok: false` rather than throwing); and a per-request line that queues calls
  rather than refusing them.
- **`discovery.ts`** is the sole namer of iCloud DAV hostnames
  (`caldav.icloud.com`, `contacts.icloud.com`), used only for the first
  discovery `PROPFIND`. Resolved home URLs are cached in `DAV_CACHE` under
  `dav:v1:<hash>:<service>` for 24 hours. Only discovery metadata is cached,
  never event or contact content. `dav_diagnose` with `refresh: true` clears
  these keys.
- DAV takes no lease. The lease guards iCloud mail connections only.

### Attachment staging (R2)

Staging a file for a draft happens outside the IMAP session. `staging/r2.ts`
writes bytes under a `staging/` prefix in the `ATTACHMENT_STAGING` bucket, which
has a one-day lifecycle rule (created out of band). `staging/presign.ts` mints
presigned upload URLs with `aws4fetch` and is the only reader of the R2 S3
credentials. A staging token expires at exactly 24 h; the bytes live 24–48 h,
so the token always dies before the bytes it names.

### Saving attachments

`mail_save_attachment` reads the chosen attachment parts in one read-only
session and closes it. Only then does `save/stage.ts` decode each part, store a
copy under the person's own prefix in the same bucket, and seal a link to it.
The link is `https://<host>/save/<token>`. It is sealed under
`SAVE_LINK_SEAL_KEY`, works for five minutes, and works once in practice, not
once for certain. The first download writes a spent mark to `SAVE_LINK_KV`
before a byte is sent. That store takes time to reach every location, so two
downloads from two places at almost the same moment can both get the file. `save/route.ts`
serves it with no sign-in, no mail connection and no lease, and is rate-limited
by `SAVE_IP_LIMITER`. A copy is deleted by its download. An unused copy is
deleted at the person's next save, when anyone tries its dead link, or by the
bucket's daily sweep within two days. The save tool refuses the autonomy key.

---

## The per-person object

`src/agent/user-agent.ts` defines `UserAgent`, one Durable Object per signed-in
person. `agentFor` in `src/agent/lease.ts` is the only place a stub is built,
from the signed-in principal's user id. The object holds:

- the connection lease;
- its own stored name (the person's user id), so its alarm knows whose grants
  to ask about;
- the recall ledger: two SQLite tables listing every vector id the person owns,
  with no text, no message ref and no address;
- one sealed autonomy record;
- the person's rules, what the rules job did, and the job's own state.

It holds no address and no password. It never opens a socket and never imports
mail, DAV, tool or auth code. The scan walks its imports at commit time to hold
that. It reaches this Worker only through `autonomySelfFetch`, which calls the
`SELF` service binding. `SELF` must name this Worker.

### The alarm

The object has one alarm. Its jobs run in a fixed order:

1. autonomy: does the key still stand?
2. the rules job;
3. recall's revocation: a pending destroy, or no grant left;
4. recall's expiry.

One predicate, `anyJobPending()`, keeps the alarm. One helper, `scheduleAlarm`,
is the only code that sets or removes it. It removes the alarm only when no job
is left, and never moves a set alarm later. The alarm never uses the autonomy
key: it reads the grant id and the arming time, and asks the sign-in store.

---

## Recall

Recall is a searchable copy of each person's recent mail. It is inherent: every
signed-in person's recent inbox and archive mail is indexed, with no switch.

- **The index fails open, so there is one way to it.** A vector-index query with
  no namespace searches everyone's vectors. So `src/recall/index.ts` is the only
  module that may name the index binding. Its reads and writes take the
  principal and nothing else, set the namespace and a metadata filter from the
  user id, and drop any match that belongs to someone else.
- **One model.** `src/recall/embed.ts` is the only reader of the AI binding and
  holds the one model id.
- **What is kept.** Per message: its vector, its opaque message reference, its
  subject line (capped) and when it was indexed. The body preview is embedded and then thrown
  away. Vectors expire after 90 days. A person holds at most 10,000.
- **The ledger comes first.** A vector id is written to the ledger before the
  vector is stored, and removed after the vector is deleted. So the ledger
  always holds every id the index holds, and a whole person's vectors can
  always be deleted.
- **Two drivers.** Both are in `src/recall/drive.ts`. The recall step runs after
  a mail, recall or change tool answers without an error. The IMAP diagnostic
  never runs one. It takes the lease once and usually opens one session, in two
  rare cases up to three, one after another. The backfill runs only when the
  person calls `mail_recall_backfill`: up to ten pages, each page taking the
  lease for its own sessions. Neither runs on the autonomy key, and neither runs
  from the alarm.
- **Pace.** Ordinary pages run at most one a minute and 200 a day per person.
  The backfill skips the minute's pause and that daily count, for a folder still
  being built only, and has its own daily cap.
- **When access ends.** The object asks, from its alarm, whether the person
  still holds any grant. Only a definite "none" destroys their vectors, within
  a day.

---

## The rules job

Every person who signs in holds an autonomy key. For a person with at least one
rule, this server acts on their new inbox mail on its own, with nobody present.
For a person with no rules, it does nothing. There are no default rules.

- **The key.** At sign-in, `src/auth/login-handler.ts` mints a second grant, for
  the autonomy client, and hands its one-time code to the person's object. The
  object exchanges it at this Worker's own token endpoint, seals the refresh
  token under `AUTONOMY_SEAL_KEY` tied to the person's user id, and keeps it.
  The key has no timer. It ends when the person holds no ordinary sign-in any
  more, within a day, or at its next use at the latest.
- **The run.** Every 15 minutes (a per-person offset spreads people out), the
  alarm runs `src/agent/job.ts`. It asks `changes_since` for new inbox mail,
  matches each message's sender address, sender domain and subject words
  against the rules, and then either flags the message or places a draft reply
  to its sender in the rule's own words. It records what it did.
- **Only four tools.** The job reaches mail only through tool calls at this
  Worker's own `/mcp`, through `SELF`, where the door takes the lease like any
  request. It can name only `account_whoami`, `changes_since`, `mail_flag` and
  `mail_compose_reply` (`AUTONOMY_TOOLS`). It never takes the lease itself.
- **Adding a rule is previewed.** `rules_add` writes nothing and returns a
  sentence naming every condition and the action, plus a confirmation.
  `rules_commit` adds it.

---

## The confirmation capability

Some writes change nothing on the first call. They return a preview and a
signed confirmation, and a commit tool applies the change when it is handed
both back unaltered. The pairs that exist:

| Preview | Commit |
|---------|--------|
| `calendar_update_event`, `calendar_delete_event`, `calendar_delete_calendar`, `calendar_respond_to_invitation`, and `calendar_create_event` with attendees | `calendar_commit` |
| `contacts_create`, `contacts_update` | `contacts_commit` |
| `mail_move`, `mail_archive`, `mail_trash`, `mail_delete_draft` | `mail_commit` |
| `rules_add` | `rules_commit` |

`src/confirm.ts` implements the token:

- Sealed with HMAC-SHA-256 over `CONFIRM_SECRET`, imported as a non-extractable
  `CryptoKey`. It fails closed on both mint and verify if the secret is absent.
- Carries a `jti` (`crypto.randomUUID()`) spent once by writing to
  `CONFIRM_KV`, and a canonical hash of the change, so any change to it before
  commit is refused.
- Lifetime `CONFIRM_TTL_SECONDS = 300`.
- KV is eventually consistent. For DAV writes, an `If-Match` ETag precondition
  backs it up and returns 412 on a race. A mail commit acts only on the
  messages the preview named, and only if they are unchanged since.

`CONFIRM_SECRET` also seals the change check's marker, under a different label.
Rotating it invalidates every confirmation in flight and every marker a client
holds. No sign-in breaks, and no stored credential is touched.

---

## Cross-cutting concerns

### Untrusted content

`src/mcp/untrusted.ts` sits above both protocol trees. Tool results that carry
outside data (mail bodies, event titles, contact fields, calendar names) are
wrapped in a fence: a preamble telling the model this is data to report, a
nonce, and a two-block trusted/untrusted split. Attendee lists for any write
are always supplied by the caller and never taken from content the server
read.

### Identifiers

Every id the assistant sees is opaque. Mail ids carry mailbox + `UIDVALIDITY` +
`UID` together; DAV ids carry the collection URL and object URL together. So an
id stands on its own and cannot be pointed at the wrong resource by editing
part of it. Paging cursors use the same codec (`src/tokens.ts`).

### Errors

`src/errors.ts` maps every failure to a fixed, closed vocabulary by the error's
*type*, never by reading a caught value's `.message` or `.stack`. DAV errors have
their own typed classes (`src/dav/errors.ts`) that share only the vocabulary.
No error text echoes a credential or a command.

---

## Safety model

Six rules are safety boundaries, not style. Each is enforced by
`scripts/forbidden-tokens.mjs`. The full reasoning is in `.claude/CLAUDE.md`,
under Conventions. This is a summary, and where the two differ, CLAUDE.md is
right.

1. **Banned transport paths.** The socket API's opportunistic TLS upgrade call,
   the transport mode that asks for it, and the cleartext IMAP port it upgrades
   from must never appear. They are named in CLAUDE.md §1 and nowhere in the
   scanned tree. Implicit TLS on 993 covers every need.

2. **No mail sending, ever.** SMTP ports (25/465/587) and mail-sending libraries
   are banned. A person reads every message before it leaves; that is the
   backstop against prompt-injected content going out. The drafts write is the
   only write that composes a message, built in exactly one module
   (`src/mail/service.ts`), and that is a *count*: zero writers is a violation
   too. The other mail writes send nothing. Two change one flag on one message
   when the user asks: read status, and the flag. The flag may also be set by
   a rule the user wrote (rule 6). A move copies a message the user already has
   into another folder, then removes the original; the copy has one counted
   site too. Three things look like sending and are reconciled in CLAUDE.md §2:
   a calendar event with attendees (iCloud sends the invitation, and the
   attendees are supplied by the caller), answering an invitation (iCloud tells
   the organiser; the user picks one of three answers), and a draft reply the
   rules job places (it stays in Drafts).

3. **One socket importer.** `cloudflare:sockets` is imported by exactly one
   file, and `connectImap()` takes no parameters. The one-connection-at-a-time
   property is defended again one layer up: two orchestrators over one private
   core and one request gate, and no concurrent combinator around either,
   around a triage verb, or around the socket open. A third layer, the lease in
   the person's `UserAgent`, works across requests. It is added to the gate, not
   a replacement.

4. **Credentials never reach a log or an error.** There are no logging calls
   anywhere under `src/`. IMAP `LOGIN` carries the password inline, so there is
   no field a redactor could target. A logging call naming the environment
   object, a grant's props or the autonomy key is banned in `scripts/` and
   `test/` too. Two decisions sit on this rule, argued in CLAUDE.md §4:
   `account_whoami` returns the whole signed-in address, and the server holds a
   sealed autonomy key for every signed-in person.

5. **Reading mail does not mark it read.** Every read opens its mailbox
   read-only. RFC 3501 says no change to the permanent state of a mailbox
   opened that way is allowed. But iCloud answered that open as read-write when
   it was probed on 2026-09-27, so whether iCloud would refuse a change there
   has not been measured. What keeps mail unread is the convention: every
   fetch peeks, the scan enforces it, and `test/read-path-wire.test.ts` holds
   the exact commands every read sends. One separate path, used only by
   `src/mail/triage.ts`, opens a mailbox in the mutating form. It marks one
   message read or unread, flags or unflags one message, moves messages, or
   moves one draft to Trash, when the user asks. The rules job may also set the
   flag through the same tool, never clear it. The path is counted, kept apart
   by type, and fetches no body. A move copies first, and removes only the one
   original whose copy iCloud proved. Nothing removes mail in place or empties
   Trash.

6. **The autonomous layer may flag and may place a draft reply, and nothing
   else.** Rules match the sender's address, the sender's domain and words in
   the subject. No model reads the message. The matcher's answer is two numbers
   and a word. A draft reply goes only to the address in the From line, in the
   rule's own words, and is never sent. From can be forged, and that is
   accepted: the person sees the address before sending. The job can name only
   four tools, and cannot send, delete, move, write a new message, answer an
   invitation or write an event.

### Enforcement

`scripts/forbidden-tokens.mjs` holds the list: pattern rules, each with a
reason printed on rejection, and count constraints that fail in **both**
directions, a duplicated owner *and* a missing one. It also checks the wrangler
config and the commit hook. Which rules exist today is a question for the
script, not for this file.

It runs from **two** gates: the test suite (`test/forbidden-tokens.test.ts`) and
`.husky/pre-commit`. Every rule carries a known-violating sample, checked by
set-equality against the rule ids, so a rule that matches nothing fails the
suite.

**Do not weaken a rule to make a commit pass.** Exclusion is by path, never by
making a rule see less. If a rule is genuinely in the way, that is a decision
about the safety boundary. Raise it.

---

## Configuration

The tracked config is `wrangler.jsonc.example` (all placeholders). The real
`wrangler.jsonc`, holding your account id, KV ids and domain, is git-ignored.

### Bindings

| Binding | Kind | What it holds |
|---------|------|---------------|
| `OAUTH_KV` | KV | The OAuth library's grants, tokens and clients; the dead-password pause markers; the rules job's status records. |
| `DAV_CACHE` | KV | Resolved CalDAV/CardDAV home URLs, 24 hours. |
| `CONFIRM_KV` | KV | Spent confirmation ids. |
| `ALLOW_LIST_KV` | KV | The stored half of the allow list. |
| `SAVE_LINK_KV` | KV | Spent save-link marks. |
| `ATTACHMENT_STAGING` | R2 | Staged and saved attachment copies, under a one-day lifecycle rule. |
| `RECALL_INDEX` | Vectorize | The recall index. |
| `AI` | Workers AI | The recall embedding model. |
| `USER_AGENT` | Durable Object | The per-person `UserAgent` (SQLite storage). |
| `SELF` | Service | This Worker, for the object's calls to its own `/mcp`. |
| `LOGIN_IP_LIMITER`, `LOGIN_ID_LIMITER` | Rate limit | Sign-in attempts per address and per Apple ID. |
| `SAVE_IP_LIMITER` | Rate limit | Save-link downloads per address. |
| `R2_ACCOUNT_ID`, `ALLOWED_APPLE_IDS_SEED` | Vars | The R2 account for presigning; the seed half of the allow list. |

### Secrets

Set with `wrangler secret put`, and in `.dev.vars` for local work:
`CONFIRM_SECRET`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`,
`SAVE_LINK_SEAL_KEY`, `AUTONOMY_SEAL_KEY` and `AUTONOMY_CLIENT_SECRET`. No Apple
credential is a secret: each person's password lives in their own grant.

### The generated hostname

The deployed hostname has one source of truth: `routes[0].pattern` in the
wrangler config.

- `scripts/hostname.mjs` reads it (falling back to `wrangler.jsonc.example` on a
  fresh clone with no real config yet).
- `scripts/write-hostname.mjs` bakes it into the git-ignored
  `src/deployed-hostname.generated.ts`, so module-init code can import it. A
  deployed Worker has no filesystem and cannot read the config at run time. It
  runs on `prepare`, `pretest`, `pretypecheck` and `predeploy`, and copies
  `wrangler.jsonc.example` → `wrangler.jsonc` if the real config is missing.
- `src/mcp/api-handler.ts` re-exports the generated constant. A hardcoded
  hostname in `src/` fails the scan.

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
npm test            # the whole suite, over 6,000 tests
npm run docs:tools  # README's tool tables match the code
```

Tests run under [`@cloudflare/vitest-pool-workers`](https://developers.cloudflare.com/workers/testing/vitest-integration/)
in two projects, because they have two different needs:

- `static` (Node) runs the few tests that read files off disk: the
  forbidden-token scan (the repository tree), the Vectorize shape pins
  (`node_modules`) and the recall import-closure check. A Workers isolate has
  no filesystem. `vitest.config.ts` names these files once.
- `workers` (real `workerd`) runs everything else, against the real Worker
  config. Tests that read source or docs there use Vite's `import.meta.glob`.

Secrets are faked in `vitest.config.ts` (`*-not-real`). Remote bindings are
off, so the vector index and AI binding reach nothing real; tests use fakes.
**No test signs in to a real Apple ID.** That is a hard rule (D-09). Never
point an automated step at a real account.

### Commits

The pre-commit hook runs the scanner and refuses a staged `.dev.vars`. Keep
commits focused; the scanner runs on every one.

### Changing safety-critical code

Before touching `src/mail/socket.ts`, `src/mail/service.ts`, `src/mail/triage.ts`,
`src/dav/transport.ts`, `src/dav/discovery.ts`, `src/agent/`, `src/recall/index.ts`,
the confirmation flow, or the OAuth and host-check setup, read the *Safety
model* above and the full reasoning in `.claude/CLAUDE.md`. These modules carry
guarantees that the scanner enforces but cannot explain. The reasons matter.

---

## Non-goals and deliberate boundaries

- **No SMTP, no sending.** A safety boundary (rule 2).
- **Acting on its own is limited to rules.** The rules job may flag a message
  and place a draft reply, with nobody present, and only for a person who wrote
  a rule (rule 6). Nothing it does sends anything. There is no other background
  work: no digests, no watchers.
- **No other iCloud services.** No Reminders, Notes or Photos.
- **iCloud is the system of record.** The server keeps these copies, and no
  others:
  - the recall index: a vector and the subject line per recent message, for 90
    days, and never a body;
  - attachment copies being staged or saved, deleted within about two days;
  - discovery metadata, for 24 hours;
  - each person's rules and what the job did, with no subject, address or text.
- **No IMAP connection pooling.** Connect, act, close, every session. The
  per-person object holds a lease, never a socket.
