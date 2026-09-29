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
can read and search your mail, draft replies into your Drafts folder, sort mail
into folders, read and manage calendar events, find free time, and read and
update contacts — all against your real iCloud account.

Several people can sign in, each with their own Apple ID and their own
app-specific password, and each reaches only their own account. Who may sign in
is an allow list you set. Every account-specific value lives in configuration
you supply. See [Deploy](#deploy).

### What the assistant can do

- **Read mail** — list, search, and read messages and attachments (including
  text extracted from PDFs), and save attachments to your own computer.
- **Find mail by meaning** — the server keeps a searchable index of your recent
  inbox and archive mail. See
  [SECURITY.md](SECURITY.md#recall-keeps-a-searchable-copy-of-your-recent-mail)
  for what it keeps and for how long.
- **Draft mail** into your iCloud Drafts folder — new messages and threaded
  replies, with staged attachments. **It cannot send.** A human reviews every
  draft and sends it by hand. This is a safety boundary, not a limitation. See
  [Safety enforcement](#safety-enforcement).
- **Sort mail** — mark a message read or unread, flag it, and move messages to
  another folder, the archive or Trash. A move is **previewed first**. A draft
  can be moved to Trash the same way. Nothing removes mail for good.
- **Say what changed** since an earlier call: new mail by sender and subject,
  and how many events changed on each calendar.
- **Manage the calendar** — list, search, read, create, update, and delete
  events and calendars, and answer invitations. Every change that is
  destructive or notifies someone is **previewed first** and only applied after
  an explicit confirm step.
- **Find free time** across all your calendars for a given duration.
- **Look up and change contacts** — search and read them, and create or update
  one. A contact change is **previewed first**.
- **Run your own rules** — rules you add can flag new inbox mail or place a
  draft reply to its sender, every 15 minutes, with nobody present. See
  [Tools → Rules](#rules).

### What it deliberately does not do

- **Send mail.** No SMTP, ever. The draft-and-review step is the backstop
  against prompt-injected email content going out under your name. A draft
  reply a rule places is still only a draft.
- **Act on its own beyond your rules.** With no rules, nothing runs. A rule can
  only flag a message or place a draft reply to its sender. No model reads your
  mail to decide what to do.
- **Keep your mail.** iCloud is the system of record. What the server does keep
  is short-lived or small: the recall index (subject lines and a numeric
  fingerprint, never the message text, for 90 days), staged and saved
  attachments (removed within about two days), which server holds your account
  (24 hours), and your rules and what they did.
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
      ├─ Contact tools ▶ CardDAV over HTTPS ──▶ contacts.icloud.com
      └─ Recall      ──▶ Workers AI (embeddings) + Vectorize (the index)

Per-person Durable Object  ──  mail lease, recall ledger, rules and their job
      │  (for a person with rules, its alarm runs the rules job every 15 minutes)
      └─ calls this Worker's own /mcp through the SELF service binding
```

- The endpoint is **OAuth-gated**. An unauthenticated request never reaches a
  tool. Apart from the OAuth sign-in endpoints, the one other public path is
  `/save/`, which serves an attachment save link and nothing else.
- IMAP runs over the Workers-native TCP socket API with implicit TLS on port
  993 — no bridge, no proxy. Each session is opened, used, and closed within a
  single request. A request may open more than one session, one after another,
  never two at once.
- Each signed-in person has one Durable Object. A mail tool call takes that
  object's short lease before it connects, so two apps signed in as the same
  person never hold two mail connections at once. A second call that finds the
  lease held is refused with a plain reason.
- The rules job runs from that object's alarm. It reaches mail only by calling
  this Worker's own `/mcp`, with a token from that person's autonomy sign-in, like
  any other client. It can call only four tools.
- CalDAV/CardDAV use [`tsdav`](https://github.com/natelindev/tsdav); resolved
  server locations are cached in KV.
- Recall turns each recent message's subject, sender and opening lines into a
  numeric fingerprint with Workers AI, and stores it in a Vectorize index, in the
  signed-in person's own partition.
- Each person's Apple credentials live only in their own OAuth grants, encrypted
  by the provider, written there when they sign in. The server holds no Apple
  credential of its own. For the rules job, each person's Durable Object also
  keeps one sealed token for a second sign-in made at the same time; see
  [SECURITY.md](SECURITY.md#autonomy-inherent). Credentials are never logged,
  never returned in a response, and never placed in an error message.

For the full design — request flow, transport internals, the safety
enforcement, and the module map — see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## Tools

<!-- tools:start. Generated by scripts/tool-table.mjs. Edit the lines in scripts/tool-table-core.mjs, then run: node scripts/tool-table.mjs --write -->
47 tools in six groups. Each tool that returns message, event or contact
text says in its description that the text is untrusted. Event titles, message
bodies and contact fields are data, never instructions.

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
| `mail_find` | Search one folder by keyword, sender, and date range. Exhaustive in that folder: an empty answer means no such mail is there. |
| `mail_recall` | Find recent mail by meaning. Ranked and best-effort: an empty answer means nothing scored high enough, not that no such mail exists. Returns message ids and subjects only; open one with `mail_get_message`. It searches a copy of your recent mail this server keeps for everyone who signs in; [SECURITY.md](SECURITY.md#recall-keeps-a-searchable-copy-of-your-recent-mail) says what is kept and for how long. |
| `mail_recall_backfill` | Fill your own recall index in one sitting, while you watch. Each call indexes up to 10 pages of 25 messages of recent inbox and archive mail, one page at a time. A 20-second time limit usually stops it after 4 or 5 pages, about 100 to 125 messages. It says how far it has got. Call again until it says the index is built. It takes no arguments and only ever fills your own index. |
| `mail_get_message` | Read one message in full by opaque id. |
| `mail_mark_read` | Mark one message read or unread. **Writes immediately** — no preview, because the same tool puts it back. Reports the state iCloud returned. |
| `mail_flag` | Flag or unflag one message. **Writes immediately** — no preview, because the same tool puts it back. Reports the flag state iCloud returned. |
| `mail_move` | Preview moving up to 25 messages from one folder to a folder you name, by folder id. Writes nothing; apply with `mail_commit`. |
| `mail_archive` | Preview moving up to 25 messages to the account's own archive folder. Refuses if the account has none, rather than guessing. Writes nothing; apply with `mail_commit`. |
| `mail_trash` | Preview moving up to 25 messages to Trash, where they can be moved back. Writes nothing; apply with `mail_commit`. |
| `mail_delete_draft` | Preview moving one draft to Trash. Acts only on a draft in the drafts folder, exactly as the preview showed it. Writes nothing; apply with `mail_commit`. |
| `mail_commit` | Apply a move, archive, Trash or draft-delete preview, only if the messages are unchanged since. Reports each message as `moved`, `copied_not_removed`, `not_copied` or `unknown`. Never removes mail for good. |
| `mail_get_attachment` | Read one attachment as text: plain text, HTML, or PDF (its text is extracted). Other types are refused. |
| `mail_compose_new` | Compose a new message **into Drafts** (never sent). |
| `mail_compose_reply` | Reply to a message **into Drafts**, threaded (never sent). |
| `mail_stage_attachment` | Stage a file to attach to a draft (from a message, raw bytes, or an upload URL). |
| `mail_save_attachment` | Save attachments to your own computer. One download link per file, valid five minutes. The local Claude session that has your folder connected (such as Claude Cowork) downloads it. |
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
| `contacts_create` | **Preview** a new contact. Writes nothing until `contacts_commit`. Lists cards that already hold a value you supplied; nothing is merged. |
| `contacts_update` | **Preview** one change to an existing contact. Send only the fields that change; the rest are kept. Writes nothing until `contacts_commit`. |
| `contacts_commit` | Apply a previewed contact create or update, using its confirmation token. |

### Changes

| Tool | What it does |
|------|--------------|
| `changes_since` | Say what changed since a marker from an earlier call: counts first, then new mail by sender, subject and whether it came from a mailing list (never a body), then each calendar's count of events added or changed and removed. Watches the inbox, or up to five folders you name. Returns a fresh marker every time. Never marks mail read. |

### Rules

These are this server's own autonomy rules, not iCloud Mail's rules. A rule
runs on its own every 15 minutes, with nobody present, and can only flag a
matching message or place a draft reply to its sender. With no rules, nothing
runs.

| Tool | What it does |
|------|--------------|
| `rules_list` | List your rules, whether the rules job is running for you, and what it did recently. Reads no mail. |
| `rules_add` | **Preview** adding a rule. Writes nothing; the preview's sentence names every condition and the action. Apply with `rules_commit`. |
| `rules_commit` | Add the rule `rules_add` previewed, using its confirmation token. |
| `rules_remove` | Remove one of your rules at once. |
| `rules_test` | Try a rule on your newest 25 inbox messages and say what it would do. Writes nothing. |
<!-- tools:end -->

Each tool's full input parameters are in its input schema, which the server
sends with the tool list, so an MCP client shows them with the tool.

---

## Requirements

| Requirement | Why |
|-------------|-----|
| **Cloudflare account, Workers Paid plan** | The free tier's 10 ms CPU budget cannot parse MIME bodies and PDF attachments. |
| **A domain on Cloudflare** | `workers.dev` and preview URLs are disabled by design, so a custom-domain route is required. |
| **Vectorize and Workers AI on the same account** | Recall stores its index in Vectorize and makes its fingerprints with a Workers AI embedding model. Both bill per use; the estimate in `src/recall/retention.ts` is about 2 cents a month for a typical person, and about 11 cents at the ceiling. |
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
npx wrangler kv namespace create SAVE_LINK

npx wrangler r2 bucket create icloud-mcp-attachments

npx wrangler vectorize create icloud-mcp-recall --dimensions=1024 --metric=cosine
npx wrangler vectorize create-metadata-index icloud-mcp-recall --propertyName=u --type=string
```

The Vectorize index holds the recall index. Create it, and its metadata index,
before the first deploy: wrangler does not create an index on deploy, and a
deploy fails until it exists. Its size (1024) and metric (cosine) cannot be
changed later. The metadata index must exist before the first vector is written,
because recall filters every search to the signed-in person with it.

Add a lifecycle rule to the bucket so staged uploads expire after one day
(Cloudflare dashboard → R2 → your bucket → Settings → Object lifecycle rules:
prefix `staging/`, delete after 1 day). This is required — the staging token
expires at 24 h and the bytes must not outlive it by much. Attachment copies made
for a save link live under the same prefix, so the rule clears them too.

### 3. Fill in `wrangler.jsonc`

Edit these values in your git-ignored `wrangler.jsonc`:

- `routes[0].pattern` → your custom domain (e.g. `icloud-mcp.your-domain.example`)
- `vars.R2_ACCOUNT_ID` → your Cloudflare account id
- `vars.ALLOWED_APPLE_IDS_SEED` → your own Apple ID, as a one-element JSON array
  string: `"[\"you@example.com\"]"`
- `kv_namespaces[].id` → the five ids from step 2

Leave the other bindings as they are. `vectorize[0].index_name` must match the
index you created. `services[0].service` must equal `name` at the top of the
file: that binding lets the rules job call this same Worker, and it must never
point at another one.

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

# 32 random bytes, base64url, sent on standard input so it is never printed:
node -e "process.stdout.write(require('crypto').randomBytes(32).toString('base64url'))" \
  | npx wrangler secret put SAVE_LINK_SEAL_KEY
```

See [`.dev.vars.example`](.dev.vars.example) for what each secret is. Two more
secrets, `AUTONOMY_CLIENT_SECRET` and `AUTONOMY_SEAL_KEY`, are set for you in
step 7.

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

### 7. Set up autonomy

```bash
node scripts/grants.mjs autonomy-setup         # shows what it would do
node scripts/grants.mjs autonomy-setup --yes   # does it
```

This creates the client the rules job signs in as, and sets
`AUTONOMY_CLIENT_SECRET` and `AUTONOMY_SEAL_KEY` through standard input. It never
prints either value. Setting a secret deploys a new version of the Worker. From
then on, every sign-in also makes that person's autonomy key. Until you run it,
sign-in works but nobody has a key, so no rules run. Running it again refuses;
`--replace` makes a new client and ends everyone's key until their next sign-in.

---

## Connect an MCP client

The MCP endpoint is `https://your-domain.example/mcp`. It uses OAuth 2.1 with
Dynamic Client Registration.

1. Add the connector URL (`https://your-domain.example/mcp`) in your MCP client.
2. The client sends you to the `/authorize` page.
3. Check that the page names your client and the address it will send you back
   to, and that it says it is not an Apple page. Above the fields it also says
   that the server keeps a searchable copy of your recent mail and, once
   autonomy is set up, that it can act on your own rules while you are away.
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
| `autonomy` | At the end of a line: this is the person's autonomy key, the second sign-in the rules job uses. It also says `never` under `expires`, because it ends with the person's ordinary connections instead. |
| `rules job ...` | A line under an autonomy row: the rules job's next wake or when it was last idle, how many times Apple refused the password, and the last outcome. |

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

**Revoking by address also ends their autonomy key**, because it is one of their
grants. What else they leave behind goes on its own:

- Their recall index is deleted within a day of their access ending.
- Their rules, what the rules did and the job's state are deleted once they hold
  no sign-in of any kind, seen on two checks a day apart.

Taking someone off the list without revoking stops their rules job before it
reads the key, but does not delete the key. Revoke to end it.

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

### More things worth knowing

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
Miniflare's local KV, R2 and Durable Objects — no live Cloudflare storage is
touched. Workers AI and Vectorize have no local simulator; see the notes on the
recall bindings in `wrangler.jsonc.example`.

Do **not** point tests or any automated step at your real Apple ID. The suite
uses fake credentials on purpose (D-09).

---

## Testing

```bash
npm test           # full suite
npm run typecheck  # tsc --noEmit
npm run scan       # the safety scanner (see below)
npm run docs:tools # checks README's tool names and table layout against the code
```

The suite has two Vitest projects. Most tests run inside the real `workerd`
runtime via
[`@cloudflare/vitest-pool-workers`](https://developers.cloudflare.com/workers/testing/vitest-integration/),
so socket and DAV code is exercised against realistic Workers constraints, not a
Node mock. A few that must read files off disk, such as the safety scanner's own
tests, run under Node. No live account is needed, and the suite never reaches
the Cloudflare account.

README's tool count and tables are generated from the code by
`scripts/tool-table.mjs`. To change a tool's line, edit
`scripts/tool-table-core.mjs` and run `node scripts/tool-table.mjs --write`. A
test fails if the tables and the registered tools disagree, or if a number in a
tool's line differs from the constant the code enforces.

---

## Safety enforcement

Six safety rules are enforced mechanically by `scripts/forbidden-tokens.mjs`,
which runs both from the test suite and from a pre-commit hook. They cover the
mail transport, sending mail (there is none), the one module that opens a
socket, logging (there is none in `src/`), reading mail without marking it
read, and the two things the rules job may do.

The rules, their reasons and the decisions recorded against them are written
out in [`.claude/CLAUDE.md`](.claude/CLAUDE.md) under *Conventions*. The script
itself is the list of what is checked today. Changing any rule is a change to
the project's safety boundary, not a refactor. The design side is in
[ARCHITECTURE.md](ARCHITECTURE.md) → *Safety model*, and the security side in
[SECURITY.md](SECURITY.md).

---

## Project layout

```
src/
  index.ts            Worker entry (the OAuth provider) and the Durable Object export
  env.ts              binding surface (KV, R2, Vectorize, AI, Durable Object, vars, secrets)
  principal.ts        who a request acts for, and the one masking function
  confirm.ts          preview-and-commit confirmation tokens
  change-marker.ts    the marker changes_since hands back
  password-pause.ts   the fifteen-minute pause after Apple refuses a password
  auth/               OAuth options + the /authorize login handler
  mcp/                MCP handler, per-request server factory, instructions, tool registrations
  mail/               IMAP: the one socket importer, session orchestrators, triage, MIME
  dav/                CalDAV/CardDAV: transport, discovery, calendar/contacts, parsers
  agent/              the per-person Durable Object: lease, autonomy key, rules and their job
  recall/             the recall index: build, sync, backfill, embedding, search
  save/               attachment save links and the /save/ download route
  staging/            R2 attachment staging + presigned uploads
  feed/               subscription-feed fetch (calendar subscriptions)
scripts/              the safety scanner, the owner's grants command, the README tool
                      table, hostname generation, smoke test
test/                 the test suite (Vitest, mostly inside workerd)
```

---

## Tech stack

Cloudflare Workers, Durable Objects (SQLite), Vectorize and Workers AI ·
TypeScript 5.9 · MCP SDK v2 (`@modelcontextprotocol/server` 2.0.0) · `agents`
0.20.1 (`createMcpHandler`) · `@cloudflare/workers-oauth-provider` 0.10.3 ·
`tsdav` 2.3.4 (CalDAV/CardDAV) · `ical.js` 2.2.1 (iCalendar **and** vCard) ·
`postal-mime` 3.0.0 (MIME) · `unpdf` 1.8.0 (PDF text) · `aws4fetch` 1.0.20 (R2
presign) · `zod` 4.4.3 (schemas) · Wrangler 4.122.0 · Vitest 4.1.10 with
`@cloudflare/vitest-pool-workers` 0.21.2.

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
