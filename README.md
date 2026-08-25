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
- **Support multiple users** or other iCloud services (Reminders, Notes,
  Photos).

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
- Your Apple credentials live only in Cloudflare Secrets. They are never
  logged, never returned in a response, and never placed in an error message.

For the full design — request flow, transport internals, the safety
enforcement, and the module map — see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## Tools

23 tools in five groups. Every tool description carries an untrusted-content
notice; event titles, message bodies, and contact fields are treated as data,
never as instructions.

### Diagnostics

| Tool | What it does |
|------|--------------|
| `mail_imap_diagnose` | Check iCloud IMAP connectivity, auth, and capabilities. |
| `dav_diagnose` | Check CalDAV/CardDAV discovery: resolved URLs, shard host, cache hit, timings. |

### Mail

| Tool | What it does |
|------|--------------|
| `mail_list_folders` | List mail folders with role and counts. |
| `mail_list_messages` | List a folder's messages, newest first (metadata + capped snippet, never bodies). |
| `mail_list_unread` | List a folder's unread mail. |
| `mail_search` | Search one folder by keyword, sender, and date range. |
| `mail_get_message` | Read one message in full by opaque id. |
| `mail_get_attachment` | Read one attachment as text (PDF text is extracted). |
| `mail_compose_new` | Compose a new message **into Drafts** (never sent). |
| `mail_compose_reply` | Reply to a message **into Drafts**, threaded (never sent). |
| `mail_stage_attachment` | Stage a file to attach to a draft (from a message, raw bytes, or an upload URL). |
| `mail_confirm_upload` | Finish a presigned attachment upload. |

### Calendar

| Tool | What it does |
|------|--------------|
| `calendar_list_calendars` | List calendars: id, name, colour, subscription flag. |
| `calendar_list_events` | List events in a date range (recurring events expand to occurrences). |
| `calendar_get_event` | Read one event in full by opaque id. |
| `calendar_search` | Find events by keyword or attendee within a range. |
| `calendar_find_free_slots` | Find free slots across all calendars for a duration and range. |
| `calendar_create_event` | Create an event. **With attendees, previews first** and returns a confirmation. |
| `calendar_update_event` | **Preview** a change; writes nothing until `calendar_commit`. |
| `calendar_delete_event` | **Preview** deleting one event; writes nothing until `calendar_commit`. |
| `calendar_commit` | Apply a previewed create/update/delete, using its confirmation token. |

### Contacts

| Tool | What it does |
|------|--------------|
| `contacts_search` | Find contacts by name or email (rows carry addresses). |
| `contacts_get` | Read one contact in full by opaque id. |

Full input parameters for each tool are in the tool descriptions themselves and
in [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Requirements

| Requirement | Why |
|-------------|-----|
| **Cloudflare account, Workers Paid plan** | The free tier's 10 ms CPU budget cannot parse MIME bodies and PDF attachments. |
| **A domain on Cloudflare** | `workers.dev` and preview URLs are disabled by design, so a custom-domain route is required. |
| **An Apple ID with an app-specific password** | iCloud requires an app-specific password for IMAP/DAV when the account has two-factor auth (it does). |
| **Node.js 20+ and npm** | For the Wrangler and Vitest toolchain. |

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
- `kv_namespaces[].id` → the three ids from step 2

The hostname is baked into the build automatically from `routes[0].pattern`;
you never edit it in code.

### 4. Set the secrets

```bash
npx wrangler secret put AUTH_SECRET            # your login password for /authorize
npx wrangler secret put APPLE_ID               # the account's Apple ID (email)
npx wrangler secret put APPLE_APP_PASSWORD     # app-specific password, not the real one
npx wrangler secret put CONFIRM_SECRET         # e.g. `openssl rand -base64 32`
npx wrangler secret put R2_ACCESS_KEY_ID       # from an R2 S3 API token,
npx wrangler secret put R2_SECRET_ACCESS_KEY   #   Object Read & Write, scoped to the bucket
```

See [`.dev.vars.example`](.dev.vars.example) for what each secret is.

### 5. Deploy and verify

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
3. Enter your `AUTH_SECRET` and approve.

The redirect-origin allowlist is `https://claude.ai` plus loopback. To authorize
a client on a different origin, add it in `src/auth/login-handler.ts`.

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
5. Reading mail never marks it read (mailboxes opened read-only, peeking fetches).

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
