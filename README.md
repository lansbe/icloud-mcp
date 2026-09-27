# iCloud MCP

An [MCP](https://modelcontextprotocol.io) server, hosted on Cloudflare Workers,
that gives an AI assistant native tool access to **iCloud Mail, Calendar, and
Contacts** — over IMAP, CalDAV, and CardDAV — without your credentials ever
leaving the server.

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Platform: Cloudflare Workers](https://img.shields.io/badge/platform-Cloudflare%20Workers-orange.svg)
![Protocol: MCP](https://img.shields.io/badge/protocol-MCP-blue.svg)

---

## What it is

iCloud MCP is a single Cloudflare Worker that speaks three Apple protocols and
exposes them to an MCP client (such as Claude) as a set of tools. The assistant
can read and search your mail, draft replies into your Drafts folder, read and
manage calendar events, find free time, and look up contacts — all against your
real iCloud account.

It was built for one person against one Apple ID, but nothing about it is
personal to that account: every account-specific value lives in configuration
you supply. See [Deploy](#deploy).

### What the assistant can do

- **Read mail** it does not send — list, search, and read messages and
  attachments (including text extracted from PDFs).
- **Draft mail** into your iCloud Drafts folder — new messages and threaded
  replies, with staged attachments. **It cannot send.** A human reviews every
  draft and sends it by hand. This is a safety boundary, not a limitation. See
  [Security](#security).
- **Manage the calendar** — list, search, read, create, update, and delete
  events. Every change that is destructive or notifies someone is **previewed
  first** and only applied after an explicit confirm step.
- **Find free time** across all your calendars for a given duration.
- **Look up contacts** by name or email.

### What it deliberately does not do

- **Send mail.** No SMTP, ever. The draft-and-review step is the backstop
  against prompt-injected email content going out under your name.
- **Act on its own.** No cron jobs, no background watchers, no digests.
- **Cache your content.** iCloud is the system of record; only discovery
  metadata (which server holds your account) is cached, for 24 hours.
- **Let anyone in.** Who may sign in is an allow list you set. Everyone else is
  refused before Apple is ever contacted. Taking somebody off the list stops
  them signing in again; ending a session they already have is a second step.
  See [Removing someone](#removing-someone).
- **Support other iCloud services** (Reminders, Notes, Photos).

---

## How it works

```
MCP client (Claude)
      │  HTTPS, OAuth 2.1 bearer token
      ▼
Cloudflare Worker  ──  OAuth provider gates every request
      │                (@cloudflare/workers-oauth-provider)
      ▼
MCP handler (/mcp)  ──  builds a fresh server per request
      │
      ├─ Mail tools  ──▶ IMAP over TLS (raw TCP socket) ──▶ imap.mail.me.com:993
      ├─ Cal tools   ──▶ CalDAV over HTTPS  ──▶ caldav.icloud.com
      └─ Contact tools ▶ CardDAV over HTTPS ──▶ contacts.icloud.com
```

- The endpoint is **OAuth-gated**. An unauthenticated request never reaches a
  tool.
- IMAP runs over the Workers-native TCP socket API with implicit TLS on port
  993 — no bridge, no proxy. A connection is opened, used, and closed within a
  single request.
- CalDAV/CardDAV use [`tsdav`](https://github.com/natelindev/tsdav); resolved
  server locations are cached in KV.
- Each person's Apple credentials live only in their own OAuth grant, encrypted
  by the provider, written there when they sign in. The server holds no Apple
  credential of its own. They are never logged, never returned in a response,
  and never placed in an error message.

For the full design — request flow, transport internals, the safety
enforcement, and the module map — see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## Tools

37 tools in five groups. Every tool description carries an untrusted-content
notice; event titles, message bodies, and contact fields are treated as data,
never as instructions.

### Diagnostics

| Tool | What it does |
|------|--------------|
| `mail_imap_diagnose` | Check iCloud IMAP connectivity, auth, and capabilities. |
| `dav_diagnose` | Check CalDAV/CardDAV discovery: resolved URLs, shard host, cache hit, timings. |
| `account_whoami` | Show which Apple ID this connection is signed in as — the full address, from this connection's own grant. |

### Mail

| Tool | What it does |
|------|--------------|
| `mail_list_folders` | List mail folders with role and counts. |
| `mail_list_messages` | List a folder's messages, newest first (metadata + capped snippet, never bodies). |
| `mail_list_unread` | List a folder's unread mail. |
| `mail_search` | Search one folder by keyword, sender, and date range. |
| `mail_get_message` | Read one message in full by opaque id. |
| `mail_mark_read` | Mark one message read or unread. **Writes immediately** — no preview, because the same tool puts it back. Reports the state iCloud returned. |
| `mail_get_attachment` | Read one attachment as text (PDF text is extracted). |
| `mail_compose_new` | Compose a new message **into Drafts** (never sent). |
| `mail_compose_reply` | Reply to a message **into Drafts**, threaded (never sent). |
| `mail_stage_attachment` | Stage a file to attach to a draft (from a message, raw bytes, or an upload URL). |
| `mail_confirm_upload` | Finish a presigned attachment upload. |

### Calendar

| Tool | What it does |
|------|--------------|
| `calendar_list_calendars` | List calendars: id, name, colour, subscription flag. |
| `calendar_create_calendar` | Create a calendar with a name and a `#RRGGBB` colour. **Writes immediately** — no preview, because it is reversible. |
| `calendar_update_calendar` | Rename a calendar, recolour it, or both. **Writes immediately** — no preview, because it is reversible. Reports which of the two actually changed. |
| `calendar_list_events` | List events in a date range (recurring events expand to occurrences). |
| `calendar_get_event` | Read one event in full by opaque id. |
| `calendar_search` | Find events by keyword or attendee within a range. |
| `calendar_find_free_slots` | Find free slots across all calendars for a duration and range. |
| `calendar_create_event` | Create an event. **With attendees, previews first** and returns a confirmation. |
| `calendar_update_event` | **Preview** a change; writes nothing until `calendar_commit`. |
| `calendar_respond_to_invitation` | **Preview** answering one invitation (accepted, declined or tentative) and who is told. A repeating invitation is answered for the whole series or refused. Writes nothing until `calendar_commit`. |
| `calendar_delete_event` | **Preview** deleting one event; writes nothing until `calendar_commit`. |
| `calendar_delete_calendar` | **Preview** deleting one calendar and every item in it; writes nothing until `calendar_commit`. The default calendar is not exempt. |
| `calendar_commit` | Apply a previewed create/update/delete or invitation answer, using its confirmation token. |

### Contacts

| Tool | What it does |
|------|--------------|
| `contacts_search` | Find contacts by name or email (rows carry addresses). |
| `contacts_get` | Read one contact in full by opaque id. |

### Changes

| Tool | What it does |
|------|--------------|
| `changes_since` | Say what changed since a marker from an earlier call: counts first, then new mail by sender and subject only, then each calendar's count of events added or changed and removed. Returns a fresh marker every time. Never marks mail read. |

Full input parameters for each tool are in the tool descriptions themselves and
in [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Requirements

| Requirement | Why |
|-------------|-----|
| **Cloudflare account, Workers Paid plan** | The free tier's 10 ms CPU budget cannot parse MIME bodies and PDF attachments. |
| **A domain on Cloudflare** | `workers.dev` and preview URLs are disabled by design, so a custom-domain route is required. |
| **An Apple ID with an app-specific password** | iCloud requires an app-specific password for IMAP/DAV when the account has two-factor auth (it does). |
| **Node.js 22.18+ and npm** | Wrangler and Vitest need 20+, but `scripts/grants.mjs` — the command that cuts off a connection — needs 22.18: it uses the synchronous module resolve hook (22.15) and built-in TypeScript type stripping (22.18) so it can call the Worker's own masking and user-id functions instead of keeping second copies. `package.json` declares the floor in `engines`, and the script says so and stops if the runtime is older. |

---

## Deploy

Every account-specific value goes in `wrangler.jsonc`, which is **git-ignored**.
The tracked template is `wrangler.jsonc.example`. `npm install` copies the
template into place on first run.

### 1. Clone and install

```bash
git clone https://github.com/russellkmoore/icloud-mcp.git
cd icloud-mcp
npm install          # also copies wrangler.jsonc.example -> wrangler.jsonc
```

### 2. Create the storage bindings

Each command prints an id. Paste it into the matching entry in `wrangler.jsonc`.

```bash
npx wrangler kv namespace create OAUTH_KV
npx wrangler kv namespace create DAV_CACHE
npx wrangler kv namespace create CONFIRM_KV
npx wrangler kv namespace create ALLOW_LIST

npx wrangler r2 bucket create icloud-mcp-attachments
```

Add a lifecycle rule to the bucket so staged uploads expire after one day
(Cloudflare dashboard → R2 → your bucket → Settings → Object lifecycle rules:
prefix `staging/`, delete after 1 day). This is required — the staging token
expires at 24 h and the bytes must not outlive it by much.

### 3. Fill in `wrangler.jsonc`

Edit these values in your git-ignored `wrangler.jsonc`:

- `routes[0].pattern` → your custom domain (e.g. `icloud-mcp.your-domain.example`)
- `vars.R2_ACCOUNT_ID` → your Cloudflare account id
- `vars.ALLOWED_APPLE_IDS_SEED` → your own Apple ID, as a one-element JSON array
  string: `"[\"you@example.com\"]"`
- `kv_namespaces[].id` → the four ids from step 2

The hostname is baked into the build automatically from `routes[0].pattern`;
you never edit it in code.

**Why your own address is in the config rather than in a secret.** The allow
list has two halves, and they are split because the two readers ask different
questions. `ALLOWED_APPLE_IDS_SEED` holds you, and it is read on **every API
request** — which has to be synchronous, and a config value is. The KV list in
step 4 holds everyone else and is read **only at sign-in**, which is already
slow enough to afford a lookup. Keeping your own address in the config means a
bad KV write can never lock you out of your own server.

### 4. Write the allow list

Everyone who may sign in, apart from you, goes in one KV document.

```bash
npx wrangler kv key put --namespace-id=YOUR_ALLOW_LIST_ID --remote \
  "allow-list:v1" '["someone@example.com"]'
```

This pastes the namespace id, while the phase runbooks use `--binding
ALLOW_LIST_KV`. Both forms are correct and they stay different on purpose: the
binding name is the better habit once your config exists, because the id is then
written down in exactly one place, but you are reading this before you have
written that config, so the id is the only handle you have.

An **empty list is valid** and is the right starting point — write `'[]'`, or
skip this step entirely, and only you can sign in. A missing, empty or malformed
document means nobody beyond the seed, never everybody. Only the exact value
`["*"]` opens it to anyone.

Read it back at any time with `wrangler kv key get`. That is the whole reason it
is a KV document and not a Workers Secret: a secret cannot be read back, so
"who is on the list?" would be a question you could not answer.

### 5. Set the secrets

```bash
npx wrangler secret put CONFIRM_SECRET         # e.g. `openssl rand -base64 32`
npx wrangler secret put R2_ACCESS_KEY_ID       # from an R2 S3 API token,
npx wrangler secret put R2_SECRET_ACCESS_KEY   #   Object Read & Write, scoped to the bucket
```

See [`.dev.vars.example`](.dev.vars.example) for what each secret is.

**There is no `AUTH_SECRET`, `APPLE_ID` or `APPLE_APP_PASSWORD` any more.** Each
person now signs in with their own Apple ID and their own app-specific password,
and those live in their own grant rather than in the server's environment. If
you are upgrading an older deployment, those three secrets are inert after the
switch and can be deleted.

### 6. Deploy and verify

```bash
npm test          # optional: full suite against a local workerd (no live account needed)
npm run deploy
npm run smoke     # confirms the live endpoint refuses an unauthenticated request
```

---

## Connect an MCP client

The MCP endpoint is `https://your-domain.example/mcp`. It uses OAuth 2.1 with
Dynamic Client Registration.

1. Add the connector URL (`https://your-domain.example/mcp`) in your MCP client.
2. The client sends you to the `/authorize` page.
3. Check that the page names your client and the address it will send you back
   to, and that it says it is not an Apple page.
4. Enter your Apple ID and your app-specific password, and approve.

Paste the app-specific password exactly as Apple showed it to you. The server
passes it to Apple unchanged, so whatever Apple gave you is what works.

Every sign-in failure looks the same on purpose — a wrong password, an address
that is not on the list and a badly-shaped value all give the same message.
That is deliberate: a message that varied would tell a stranger who is on the
list. If you are stuck, check the address and re-copy the password.

The redirect-origin allowlist is `https://claude.ai` plus loopback. To authorize
a client on a different origin, add it in `src/auth/login-handler.ts`.

---

## Removing someone

**It is two steps, and doing only the first leaves them signed in.**

### Step 1 — take them off the list, so they cannot sign in again

```bash
npx wrangler kv key put --namespace-id=YOUR_ALLOW_LIST_ID --remote \
  "allow-list:v1" '["the-remaining-addresses@example.com"]'
```

No deploy needed. The list is read fresh at every sign-in, so the next one they
attempt is refused.

### Step 2 — end the session they already have

Step 1 stops new sign-ins. It does **not** end a session already running: their
existing token keeps working, because the token itself is the evidence that they
passed the list check when they signed in.

One command does this. **Look first:**

```bash
node scripts/grants.mjs list
```

That prints every connection to this server, grouped by person, each person
shown by a masked address. One line per connection:

| Column | What it means |
|--------|----------------|
| the id | The connection's own id. This is what you type to revoke just one. |
| `client "..."` | Which app it is — Claude on the web, Claude Code, and so on. |
| `created` | The day somebody signed in to make it. |
| `expires` | The day it runs out, or `never`. A login made now never expires. |
| `client present` / `client gone` | Whether the app's registration still exists. `client gone` means that connection is already dead — its next refresh is refused whatever you do. |

**Then cut them off:**

```bash
node scripts/grants.mjs revoke --address "their-address@example.com" --yes
```

**Without `--yes` nothing is deleted.** Leave it off and the command prints
exactly what it would cut, and says so. That is the safe way to check you have
the right person before anything happens. You can also revoke one connection
rather than all of somebody's, by giving its id instead of `--address`.

**It deletes their tokens as well as their connection**, and that is the part
that matters. The server checks an access token against its own token record.
That record carries its own copy of the connection and never looks at the
connection itself. So deleting only the connection stops their next refresh, but
the access token they already hold keeps working until it expires, which can be
up to one hour.

Once both are gone, their next request is refused and their client shows a
sign-in page. The store is eventually consistent, so allow about a minute for
the deletes to be seen everywhere.

The script runs as you, through wrangler's own login, and reads the live store —
never a local copy. There is deliberately no web page for this: a revoke
endpoint would be new attack surface on a server that reaches real mail, for a
job you do a few times a year. Run `node scripts/grants.mjs --help` for every
form.

### Housekeeping — clearing out old app registrations

Every app that connects registers itself first. That registration is a small
record in the same store as the connections, **anyone on the internet can make
one** (the OAuth spec requires the endpoint to be open), and it does not expire.
Nothing else removes them, so they pile up.

Small is now enforced rather than hoped for: the server refuses a registration
over 8 KiB, with more than eight redirect addresses, with any one of them over
512 characters, or with a name over 256. Every real registration seen on this
server is an order of magnitude under all four, so this should refuse nothing. If
a real app ever is refused, those are the four numbers to raise.

`list` tells you how many are lying around. To see them and clear them out:

```bash
node scripts/grants.mjs prune-clients          # shows what it would delete
node scripts/grants.mjs prune-clients --yes    # deletes it
```

**It only ever deletes a registration that no connection was using in either of
the two checks it makes.** A registration still attached to somebody's live
connection is never deleted: removing one signs that person out, even though
their connection itself is perfectly fine. It checks once to show you the list
and again immediately before deleting, so an app that connects while you are
reading the list is safe.

What it cannot do is close the last second. A sign-in that completes between the
second check and the delete would still be cut off — the store has no
transactions, so that window cannot be closed, only made small. Run this when
nobody is connecting, and if it does happen the recovery is one sign-in.

The run tells you if the second check saved anybody, so `Deleted 0 client
records.` is never the whole story.

This does not replace step 2 above. Revoking a connection is how you end
somebody's session; this just sweeps up the leftovers.

### Why it works like this

The per-request check has to be synchronous, and a KV read is not. So the check
on every request asks whether the **seed** — your own address, from the config —
is usable, and serves any well-shaped grant. The full list is consulted at
sign-in, which is already an async path.

The alternative was checking every request against the seed alone, which sounds
stricter and is actually broken: the seed holds only you, so somebody you had
just added to the list would sign in successfully and be refused on their very
next request. They would never get a working session at all.

### Three more things worth knowing

**They are not told they were removed.** Their client sees a sign-in page again,
the same one anybody who was never on the list sees. If you want them to know,
tell them yourself.

**Removing yourself is different.** Your address is the seed in `wrangler.jsonc`,
so taking it out means editing the config and deploying. An unusable seed
refuses every request from everybody, immediately — that is the fail-closed
edge, and it is why your own address does not live in KV.

**An empty or unreadable list means nobody beyond the seed.** The server refuses
rather than guessing. Only the exact value `["*"]` opens it to anyone.

**After you change an app-specific password at Apple, sign in again and then
revoke the connections that still hold the old one.** They fail at Apple, which
does no harm on its own — but a failure at Apple pauses that person for fifteen
minutes, and the pause is per person rather than per connection. So one app still
carrying the dead password can keep pausing the apps you have already fixed.
`node scripts/grants.mjs list` shows the date each connection was made; the ones
made before you changed the password are the stale ones.

**Revoke those by id, one at a time — not with `--address`.** `--address` takes
*every* connection under that person, including the fresh one you just made by
signing in again, so using it here forces yet another sign-in. Read the ids off
the `created` column and pass them:

```bash
node scripts/grants.mjs revoke <old-id> <another-old-id> --yes
```

This is sharper than it used to be: connections never expire now, and each
sign-in makes two of them, each holding its own encrypted copy of the
app-specific password.

---

## Local development

```bash
cp .dev.vars.example .dev.vars   # then fill in the values
npx wrangler dev                 # runs the Worker locally
```

`.dev.vars` is git-ignored and refused by the pre-commit hook. Local runs use
Miniflare's local KV/R2 — no live Cloudflare storage is touched.

Do **not** point tests or any automated step at your real Apple ID. The suite
uses fake credentials on purpose (D-09).

---

## Testing

```bash
npm test          # full suite
npm run typecheck # tsc --noEmit
npm run scan      # the safety scanner (see below)
```

Tests run inside the real `workerd` runtime via
[`@cloudflare/vitest-pool-workers`](https://developers.cloudflare.com/workers/testing/vitest-integration/),
so socket and DAV code is exercised against realistic Workers constraints, not a
Node mock. ~2,400 tests, no live account required.

---

## Safety enforcement

Five safety rules are enforced mechanically by `scripts/forbidden-tokens.mjs`,
which runs both from the test suite and from a pre-commit hook:

1. No opportunistic-TLS transport paths (implicit TLS on 993 only).
2. No mail sending — no SMTP, one draft-write path, enforced as a count.
3. One and only one module may open a TCP socket.
4. No credential ever reaches a log or an error (there is no logging in `src/`).
5. Reading mail never marks it read (read paths open mailboxes read-only, fetches peek). One separate path marks a single message read or unread, only when you ask.

Changing any of these is a change to the project's safety boundary. The rules,
their reasons, and how they are enforced are documented in
[ARCHITECTURE.md](ARCHITECTURE.md) → *Safety model*.

---

## Project layout

```
src/
  index.ts            Worker entry (the OAuth provider)
  env.ts              binding surface (KV, R2, vars, secrets)
  auth/               OAuth options + the /authorize login handler
  mcp/                MCP handler, per-request server factory, tool registrations
  mail/               IMAP: the one socket importer, session orchestrator, MIME
  dav/                CalDAV/CardDAV: transport, discovery, calendar/contacts, parsers
  staging/            R2 attachment staging + presigned uploads
  feed/               subscription-feed fetch (calendar subscriptions)
scripts/              hostname generation, the safety scanner, smoke test
test/                 ~2,400 tests, run inside workerd
```

---

## Tech stack

Cloudflare Workers · TypeScript · MCP SDK v2 (`@modelcontextprotocol/server`) ·
`agents` (`createMcpHandler`) · `@cloudflare/workers-oauth-provider` · `tsdav`
(CalDAV/CardDAV) · `ical.js` (iCalendar **and** vCard) · `postal-mime` (MIME) ·
`unpdf` (PDF text) · `aws4fetch` (R2 presign) · `zod` (schemas).

---

## Contributing

Issues and pull requests are welcome. Before changing anything under `src/`,
read [ARCHITECTURE.md](ARCHITECTURE.md) — especially the *Safety model*, which
the scanner enforces on every commit. To report a security issue, see
[SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE) © 2026 Russell Moore.

This project is not affiliated with or endorsed by Apple Inc. "iCloud" and
"Apple" are trademarks of Apple Inc.
