<!-- GSD:project-start source:PROJECT.md -->

## Project

**iCloud MCP**

An MCP server hosted on Cloudflare Workers that proxies iCloud Mail (IMAP), Calendar (CalDAV), and Contacts (CardDAV), giving Claude native tool access to the Apple ecosystem. Claude can read and search mail, draft replies into the iCloud Drafts folder, read and manage calendar events, and look up contacts — all without credentials ever leaving the server.

Several people can sign in, each with their own Apple ID and their own Apple app-specific password, and each reaching only their own account. The immediate driver is a job search: drafting thank-you notes, replying to recruiters, and finding calendar slots. The longer arc is moving Claude from "a thing you paste context into" toward a genuine personal assistant.

**Core Value:** Claude can read your real iCloud mail and calendar, and prepare real work against them — a draft sitting in your Drafts folder, an event on your calendar — without you ever copying and pasting.

### Constraints

- **Tech stack**: Cloudflare Workers, TypeScript, MCP TypeScript SDK — consistency with the existing `code-assist` and `engram` servers.
- **Runtime**: Workers has no persistent connections and a bounded CPU/wall-clock budget per request. IMAP sessions must be established and torn down within a single request, or pooled through Durable Objects.
- **Transport**: IMAP must go over the Workers-native TCP Sockets API (`connect()` from `cloudflare:sockets`) with implicit TLS on port 993. No intermediary bridge.
- **Security**: Server secrets exist only in Cloudflare Secrets. Each person's app-specific password exists only in their own sign-ins' encrypted props. Their autonomy key exists only in their own Durable Object, sealed. None of these may ever appear in tool responses, error messages, or logs. The MCP endpoint must be authenticated — it reaches real personal mail.
- **Safety**: Claude cannot send mail. Claude cannot perform a destructive calendar operation in a single call.
- **Attachment staging**: Attaching files to drafts requires server-side file storage (R2 or KV), since Workers cannot hold files across requests.

<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->

## Technology Stack

## 0. The load-bearing question, answered definitively

- `secureTransport: "on"` — TLS is negotiated immediately when the socket opens. This is what IMAP-over-993 (implicit TLS) needs.
- `secureTransport: "starttls"` — plaintext until you explicitly call `.startTls()` on the socket, which returns a **new** socket object (the old one becomes unusable). This is for STARTTLS-style protocols (SMTP submission on 587, IMAP on 143 with STARTTLS).
- Works from a **plain stateless Worker `fetch()` handler** — no Durable Object required. DOs are only needed if you want a socket/connection to *outlive* a single request.
- **Socket lifetime is tied to the request** in a plain Worker. In a Durable Object, an open socket keeps the DO alive and billing (up to 15 minutes per connection) — relevant only if you later decide to pool IMAP connections across calls (this project's constraints explicitly rule that out for now: "IMAP sessions must be established and torn down within a single request").
- **Disallowed:** outbound connections to Cloudflare's own IP ranges, `localhost`, private network IPs, and outbound port 25 (SMTP send — irrelevant here since this project explicitly excludes SMTP send). Port 993 is not restricted.
- Concurrent open sockets count toward a per-Worker connection limit (exact numeric ceiling not published on this page; not a concern at single-user IMAP-then-close scale). *(2026-09-23: this reasoning was made for the single-user design, and the design has since changed — several people now sign in. The conclusion still holds, because each request still connects, acts and closes; what has changed is the number of people who can be doing that at once.)*

## Recommended Stack

*(2026-09-28: the tables below are the research of 2026-08-11, and the build has moved on
since. `package.json` is what counts. It pins `tsdav` 2.3.4, `wrangler` 4.122.0 and
`@cloudflare/vitest-pool-workers` 0.21.2. `vcard4` was never added: vCard goes through
`ical.js`, the fallback the table names. `aws4fetch` was added, to presign attachment
uploads to R2.)*

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| Cloudflare Workers (`workerd`) | current (compatibility_date pinned per deploy) | Hosting runtime | Only platform offering both raw TCP sockets (`connect()`) and HTTP fetch from the same edge runtime — required to speak IMAP, CalDAV, and CardDAV from one process |
| TypeScript | 5.x | Language | Matches existing `code-assist` / `engram` servers; Workers-first tooling assumes TS |
| Wrangler | **4.121.0** (published today, moves fast — pin a minor and re-check before each milestone) | Build/deploy CLI | Current CLI; verified via `npm view wrangler version` against live registry |
| `agents` (Cloudflare Agents SDK) | **0.20.1** | MCP server hosting on Workers | See Section 1 below — supplies `createMcpHandler`, the current recommended way to host an MCP server on Workers |
| `@modelcontextprotocol/server` | **2.0.0** | MCP server-side protocol implementation | See Section 1 — the MCP TypeScript SDK split into `server`/`client` packages in its v2 release, which landed as the **stable** line alongside the 2026-07-28 MCP spec. `agents@0.20.1`'s peer dependency pins exactly `@modelcontextprotocol/server: 2.0.0` |
| `@cloudflare/workers-oauth-provider` | **0.10.3** | OAuth 2.1 provider (authorization server side) for the MCP endpoint | See Section 2 |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `tsdav` | **2.3.1** | CalDAV + CardDAV client | Explicitly lists Cloudflare Workers as a supported target runtime (confirmed in project `AGENTS.md`). Only deps are `xml-js` (pure JS) and `debug` (Workers-safe) — no Node built-ins. Use for `PROPFIND` discovery, `REPORT`/`calendar-query`, and vCard/iCal object CRUD against `caldav.icloud.com` and iCloud's CardDAV endpoint. |
| `ical.js` | **2.2.1** | Parse/serialize iCalendar (`.ics`, RFC 5545) | Zero dependencies, written for "the web" per its own docs — works in Workers with no shims. Use for parsing CalDAV `REPORT` responses and building `.ics` bodies for event `PUT`. |
| `vcard4` | **4.0.5** | Parse/serialize vCard (`.vcf`, RFC 6350) | TypeScript-native RFC 6350 implementation; no Node-only deps identified. Use for CardDAV contact objects. If it proves awkward in practice, ical.js's companion vCard/jCard support (same library, same zero-dep guarantee) is a fallback within the same package. |
| `postal-mime` | **3.0.0** | Parse raw MIME/RFC822 message bodies from IMAP `FETCH` | Zero dependencies, explicitly built for "browser, Web Workers, Node.js, and serverless environments (like Cloudflare Email Workers)" — this is the same runtime family as this project. Use to turn raw `FETCH BODY[]` bytes into structured `{subject, from, html, text, attachments}`. |
| `unpdf` | **1.8.0** | Extract text from PDF attachments | Ships a serverless PDF.js build with the `canvas` native dependency mocked out and marked fully **optional** (`peerDependenciesMeta: { "@napi-rs/canvas": { optional: true } }`) — confirmed `extractText()` does not need canvas at all; canvas is only required for `renderPageAsImage()`, which this project doesn't need. Explicitly tested against Cloudflare Workers per its own docs. |
| `zod` | 4.x (peer of `agents`) | Input schema validation for MCP tool definitions | Required peer dependency of `agents@0.20.1`; use for every tool's `inputSchema`. |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| `wrangler.jsonc` | Worker configuration | Cloudflare's current recommendation for **new** projects (see Section 8) — some newer config surface (e.g. Durable Object migrations, newer bindings) is JSON-only going forward |
| `@cloudflare/vitest-pool-workers` | Run Vitest tests **inside** the actual `workerd` runtime | Latest **0.18.4**; requires **Vitest 4.1+** (Vitest itself currently at 4.1.10). This is the correct way to test `connect()`-based IMAP code and DAV parsing against realistic Workers constraints, not a Node mock. |

## Installation

# Core — MCP server on Workers

# OAuth for the MCP endpoint

# CalDAV / CardDAV

# iCalendar / vCard parsing

# MIME + PDF

# Dev dependencies

## 1. MCP server on Workers — `agents` / `createMcpHandler`, not `McpAgent`

## 2. MCP OAuth — minimum viable for a single-user server

*(2026-09-23: this heading and the reasoning under it were written for the
single-user design, and the design has since changed. The recommendation
survived the change — the provider still owns the ceremony and only the identity
step is this project's — but "minimum viable" was decided against a server with
one account, and that is no longer what this is.)*

## 3. IMAP over Workers TCP — no viable off-the-shelf client; hand-roll it

| Library | Why it fails on Workers |
|---------|--------------------------|
| `imapflow` (1.6.6) | Directly requires Node's `net`/`tls` built-ins internally (not just as listed npm deps — this is source-level `require('net')`/`require('tls')`), plus depends on `pino` (logging, Node-oriented), `socks` (Node proxy sockets), `iconv-lite`, `@zone-eu/mailsplit`. None of this is written against `cloudflare:sockets`. Community reports (Bun/Ionic issue trackers) confirm the `net`/`tls`/`zlib` requirement breaks outside real Node. |
| `node-imap` (`imap` on npm, 0.8.19) | Same problem — built directly on Node's `net`/`tls` modules and `readable-stream`. Unmaintained relative to imapflow. |
| `emailjs-imap-client` (3.1.0) | Depends on `emailjs-tcp-socket`, a Node/browser TCP shim — not `cloudflare:sockets`. Would need to be forked and rewritten at the socket layer to run on Workers; at that point you have written a custom client anyway. |

## 4. CalDAV / CardDAV — `tsdav`

## 5. iCalendar and vCard parsing — `ical.js` + `vcard4`

- `node-ical` — despite the name suggesting parity with `ical.js`, it is oriented at Node (file/URL fetching helpers baked in) and pulls in more surface than needed for parsing an already-fetched DAV response body. Not recommended.
- `ics` (npm) — a *generator* for `.ics` files aimed at calendar invite creation, not a general parser for arbitrary CalDAV REPORT responses. Narrower than what's needed; `ical.js` covers both parse and serialize in one zero-dep package, so there's no reason to add a second library just for generation.

## 6. MIME and PDF handling — `postal-mime` + `unpdf`

## 7. Storage — KV vs R2 vs Durable Objects

| Use case | Recommendation | Why |
|----------|-----------------|-----|
| **(a) Staging files for a draft attachment** | **R2** | R2 is built for object/blob storage — "large object storage... file storage like images, videos, and PDFs" per Cloudflare's own storage-choice guidance, with strong per-object consistency and no egress fees. An attachment staged before an IMAP `APPEND` is exactly this shape: write once, read once shortly after, delete or let expire. KV is the wrong tool here — it's tuned for small, frequently-read values, not binary blobs. |
| **(b) Caching message lists** | **KV** | KV is explicitly positioned for "frequently read, infrequently written" data with global edge read latency in the 500µs–10ms range — a perfect fit for a folder's message-list summary that Claude might re-request across a session. Accept KV's eventual consistency here; a slightly stale list is a non-issue for a personal assistant tool, and it's explicitly *not* the system of record (IMAP/iCloud is, per `PROJECT.md`'s "local caching is not a product feature" constraint). |
| **(c) Holding an IMAP connection across calls** | **Not recommended — and not needed.** If ever attempted, only a Durable Object could do it (a plain Worker's socket dies with the request, confirmed in Section 0). But an open socket keeps a DO alive and billing for up to 15 minutes per connection, adding real architectural complexity (single-instance bottleneck, connection health-checking, reconnect-on-idle-timeout logic) for a personal, low-frequency-use tool. This aligns with the project's own constraint: "IMAP sessions must be established and torn down within a single request." Recommend leaving this door closed entirely rather than half-opening it — connect, authenticate, do the work, `LOGOUT`, close, every single tool call. |

## 8. Tooling — Wrangler and testing

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|--------------------------|
| Hand-rolled IMAP client over `cloudflare:sockets` | `cf-imap` (npm, v1.0.0) | If a licensing check clears its `Proprietary` terms for personal use and a short spike proves it reliable against `imap.mail.me.com` — could meaningfully cut Phase 1 scope. Not recommended as the default given its 2-day track record at time of writing. |
| `createMcpHandler` (stateless) | `McpAgent` (Durable-Object-backed, deprecated) | Only if this project later needs true cross-request session state at the MCP layer itself (e.g., long-lived IMAP IDLE push notifications) — and even then, Cloudflare's own migration guidance is to keep the stateless handler as the primary path and add a narrow stateful route alongside it, not to revert wholesale. |
| `@cloudflare/workers-oauth-provider` with a minimal first-party auth handler | Static bearer token in a `fetch` guard | If OAuth 2.1 compliance is deliberately deprioritized in favor of the simplest possible implementation — acceptable technically for a single-user server never exposed to third-party MCP clients, but forfeits the token lifecycle/revocation properties `PROJECT.md` already committed to. *(2026-09-23: this alternative was weighed for the single-user design, and the design has since changed. It is no longer available at all — with several people signing in, a static shared token has nobody to identify, and the revocation properties it forfeits are now the mechanism for removing one of them.)* |
| `wrangler.jsonc` | `wrangler.toml` | Only relevant if importing/merging config from an existing TOML-based Worker (e.g., the sibling `code-assist`/`engram` servers, if those still use TOML) — check their config format for estate consistency before finalizing. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|--------------|
| `@modelcontextprotocol/sdk` (v1.x, unified package) | Legacy line; Cloudflare's `agents@0.20.1` pins its peer dependency to the v2 split packages, not v1 — building against v1 fights the current Agents SDK | `@modelcontextprotocol/server` (2.0.0) + `@modelcontextprotocol/client` (2.0.0) |
| `McpAgent` (`agents/mcp`) | Cloudflare has explicitly deprecated and feature-frozen it | `createMcpHandler` from `agents/mcp/server` |
| SSE transport for the MCP endpoint | Deprecated by Cloudflare in favor of Streamable HTTP; no reason to build new on a deprecated transport | Streamable HTTP (the default with `createMcpHandler`) |
| `imapflow` | Hard dependency on Node's `net`/`tls` built-ins plus several Node-oriented transitive deps (`pino`, `socks`, `iconv-lite`) — will not run on Workers without a from-scratch socket-layer rewrite, at which point you've written a custom client anyway | Hand-rolled minimal IMAP client over `cloudflare:sockets` `connect()` |
| `node-imap` / `imap` (npm) | Same `net`/`tls` dependency problem as imapflow; also less actively maintained | Same as above |
| `emailjs-imap-client` | Depends on `emailjs-tcp-socket`, a Node/browser TCP shim, not `cloudflare:sockets` | Same as above |
| `letterparser` | Effectively unmaintained (~2 years since last publish); its own docs warn against parsing large messages and require full-ICU Node builds for some code paths | `postal-mime` |
| `node-ical` | Node-oriented convenience wrapper (built-in fetch/file helpers) around functionality `ical.js` already covers with zero deps and an explicit web/Workers orientation | `ical.js` |
| Workers **free tier** for this project | 10ms CPU/request is not enough to parse MIME bodies and PDF attachments | Workers **Paid plan** (30s default CPU, extendable to 5 min via `cpu_ms`) |
| Pooling an IMAP connection across requests via Durable Objects | Adds real complexity (single-instance bottleneck, health checks, idle-timeout reconnects) for a personal, low-QPS tool where the project has already ruled this out in `PROJECT.md` | Connect → auth → act → `LOGOUT` → close, every call |

## Stack Patterns by Variant

- Consider it as a drop-in replacement for the hand-rolled IMAP client to cut Phase 1 scope.
- Because it claims full RFC 9051 compliance and the exact command set this project needs (`LOGIN`, `SELECT`, `FETCH`, `SEARCH`, `APPEND`, `LOGOUT`) — but treat this as a scoped spike, not a default, given its 2-day track record at time of research.
- Keep `@cloudflare/workers-oauth-provider` wired in regardless (it's the spec-compliant path and this project's own `PROJECT.md` already committed to it), but minimize `MyAuthHandler` to the smallest possible first-party check (a shared secret set via `wrangler secret`) rather than building out a full login UI.
- Because the goal is gating the endpoint, not building an identity system — the OAuth *mechanics* matter for spec compliance and token revocation, not the identity *ceremony*.

*(2026-09-28: these four bullets lost their opening lines when this summary was generated,
and both choices they describe are closed. The IMAP client is hand-rolled, and `cf-imap` was
never used. Sign-in has been per person since the Phase 13 cutover: each person signs in with
their own Apple ID and app-specific password on a real login page, and there is no shared
secret.)*

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|------------------|-------|
| `agents@0.20.1` | `@modelcontextprotocol/server@2.0.0` (exact peer pin, not a range) | Verified via `npm view agents peerDependencies` against the live registry — do not mix with `@modelcontextprotocol/sdk@1.x` |
| `agents@0.20.1` | `zod@^4.0.0` | Required peer; also required by MCP tool `inputSchema` definitions |
| `@cloudflare/vitest-pool-workers@0.18.4` | `vitest@^4.1` | Confirmed in Cloudflare's Vitest 3→4 migration guide |
| `@cloudflare/workers-oauth-provider` | Any version **≥ 0.10.3** | CVE-2025-4143 (redirect URI validation) and CVE-2025-4144 (PKCE bypass) predate this line — do not pin below it |

## Sources

- `developers.cloudflare.com/workers/runtime-apis/tcp-sockets/` — live fetch; `secureTransport` enum, port restrictions, socket lifetime, DO-vs-plain-Worker behavior (HIGH confidence, official docs)
- `developers.cloudflare.com/agents/model-context-protocol/guides/remote-mcp-server/` — live fetch; `createMcpHandler` recommendation, McpAgent deprecation
- `developers.cloudflare.com/agents/model-context-protocol/transport/` — live fetch; SSE deprecation in favor of Streamable HTTP
- `developers.cloudflare.com/agents/model-context-protocol/authorization/` — live fetch; OAuth Provider Library wiring pattern
- `developers.cloudflare.com/agents/model-context-protocol/apis/agent-api/` — live fetch; explicit "deprecated and feature-frozen" language for McpAgent
- `developers.cloudflare.com/agents/model-context-protocol/mcp-handler-api/` and `.../apis/handler-api/` — live fetch; `createMcpHandler` signature, MCP SDK v2 requirement, stateless-handler tradeoffs
- `developers.cloudflare.com/workers/platform/storage-options/` — via search snippet; KV vs R2 vs Durable Objects guidance
- `developers.cloudflare.com/workers/platform/limits` and Cloudflare's 2025-03-25 CPU-limits changelog — via search snippet; free-tier 10ms vs paid-tier 30s/5min CPU
- npm registry (`npm view` / `registry.npmjs.org`), live queries — exact current versions for: `wrangler` (4.121.0), `agents` (0.20.1), `@modelcontextprotocol/sdk` (1.30.0) and `@modelcontextprotocol/server`/`client` (2.0.0), `@cloudflare/workers-oauth-provider` (0.10.3), `tsdav` (2.3.1), `ical.js` (2.2.1), `vcard4` (4.0.5), `postal-mime` (3.0.0), `unpdf` (1.8.0), `@cloudflare/vitest-pool-workers` (0.18.4), `vitest` (4.1.10), `cf-imap` (1.0.0), plus dependency trees for `imapflow`, `imap`, `emailjs-imap-client`, `tsdav`, `postal-mime`, `unpdf` — HIGH confidence, live registry data, not training data
- `github.com/modelcontextprotocol/typescript-sdk` — live fetch of README; v1→v2 split, v2 as current stable line alongside 2026-07-28 spec
- `blog.modelcontextprotocol.io/posts/sdk-betas-2026-07-28/` and `blog.modelcontextprotocol.io/posts/2026-07-28/` — via search snippet; v2 SDK beta→stable timeline, package-size/perf claims
- `github.com/Exerra/cf-imap` and `docs.exerra.xyz/docs/npm-packages/cf-imap/v1.0.0/intro` — live fetch; command coverage claims, license flag, pre-1.0 stability caveat (LOW confidence — single source, unverified license, 2-day-old package)
- `github.com/natelindev/tsdav/blob/main/AGENTS.md` — live fetch; explicit Cloudflare Workers target-runtime confirmation
- `unjs.io/packages/unpdf` — live fetch; confirms `extractText()` does not require the optional canvas peer dependency

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

These six are safety boundaries, not style preferences. Each one states its
reason, because a rule without a reason is a rule a future session will reason
its way around.

Read this before writing code. The scan and the commit hook described at the
bottom are *detective* controls — they catch a violation after it is written.
This section is the *preventive* one, and it is the only layer that stops the
violation being authored at all.

### 1. Banned transport paths

`startTls()`, the `"starttls"` value of `secureTransport`, and port 143 must
never appear in this codebase.

`startTls()` is the worst-documented and least reliable path in
`cloudflare:sockets`. `workerd#2712` tracks it and was still open as of
2026-06-10 with no confirmed fix. Port 143 is cleartext IMAP and exists only to
be upgraded by that call, so banning one without the other bans neither.

Nothing is given up by this. Implicit TLS on port 993 covers every need this
project has: the socket is encrypted from the first byte, there is no upgrade
step to get wrong, and iCloud serves IMAP there. There is no point on this
project's roadmap where the opportunistic path is the answer.

This file is the correct home for these token names. `scripts/forbidden-tokens.mjs`
treats them as forbidden anywhere in the scanned tree — `src/`, `scripts/`, and
`test/` — so a source comment spelling them out would fail the very check it was
trying to explain. `.planning/` is not scanned, which is why the token names may
appear there. That is why
`src/mail/socket.ts` describes them in prose and points here instead.

### 2. No mail sending, ever

SMTP submission ports (25, 465, 587) and mail-sending libraries such as
`nodemailer` and `worker-mailer` are banned.

The reason is not scope. Claude drafts; the human reviews and sends. That human
step is this project's actual backstop against prompt-injected content in an
email reaching an outbound message — the model reads untrusted text from
strangers all day, and the only thing standing between that and a message sent
under the user's name is a person looking at it first. Removing the step would
be a safety regression dressed up as a feature.

A draft reaches the iCloud Drafts folder via IMAP `APPEND`. The other mail
writes go through the separate path in §5 under "One path may change a mailbox,
and it is not a read path", and none of them sends anything. Two change one flag
on one message, when the user asks: read status, and the flag. The flag may
also be set by a rule the user wrote, with nobody present (§6). One moves mail.
It copies a message the user already has into another folder, then removes the
original. That copy places a message, so it is now the one other write that
does. It only ever places a copy of mail already in the account, never new
content. It has one counted site, like the drafts write. The drafts write is
still the only write that composes a message.

**That write is constructed in exactly one module, `src/mail/service.ts`, and
the constraint is a count rather than a prohibition.** Zero constructors is as
much a violation as two, for the same reason the socket choke-point's count is:
a prohibition is trivially satisfied by a module that was deleted, renamed or
emptied, and losing the whole capability is quieter than gaining a duplicate of
it — nothing fails on the way out, because the tests that covered the deleted
code are deleted with it. This is enforcement of the boundary the paragraph
above already states, not a new boundary; the boundary did not grow.

What the count deliberately does not see is the destination. The mailbox is a
variable at the construction site rather than a literal, so the rule guarantees
**one writer** and not **one destination**. The destination is held one layer up
instead, by a byte-exact assertion on the command line recorded through the
in-memory duplex — which reads the mailbox that was actually written rather than
the shape of the line that wrote it. A regex cannot see a mailbox held in a
variable; a test that reads the recorded command line can. Two evasions sit
outside the pattern's reach as well — a command line carrying a literal tag, and
the command word held in a variable and handed to the generic sender — and both
are named in the rule's own docstring, because a rule believed to prove more than
it does is worse than one whose limits are written down.

Nothing is given up here either. A second path that places a message would be a
second thing this project can do to the user's account. So one arrives only with
a decision, never as a refactor. The flag changes arrived that way, in Phases 20
and 21, and place no message. The move's copy arrived that way too, in Phase 21,
and places only a copy of mail the user already has.

One consequence lands on every module added under `src/` from now on. The rule's
scope is the whole source tree and it walks that tree on every commit, so
**describe this command by role and never by name** — "the write", "placing the
message into the drafts folder" — exactly as § 1 describes the banned transport
paths by role. A source comment spelling it out would fail the very check it was
trying to explain, and the failure arrives as a pre-commit rejection in the
middle of an unrelated plan, with no obvious cause and a tempting one-character
"fix" to the pattern.

#### Calendar invitations are not this rule's subject

Phase 5 adds a CalDAV write path that can carry attendees, and an event written
with attendees results in those people receiving a real invitation. That is
CALW-06, decided on 2026-08-21. It looks like the thing the rule above forbids
and it is not, so the argument is recorded here rather than left to be
re-derived.

1. **§2's reason is about prose, not about delivery.** The rule's stated ground,
   two paragraphs up, is that a message Claude composed is prose written in the
   user's voice, and that the human review step is the backstop against
   prompt-injected content reaching an outbound message. That is a claim about
   what the content *is*. It is not a claim that no byte may leave this Worker.

2. **This server still sends no mail.** No submission port is opened, no
   mail-sending library is linked, and no second construction site for the
   drafts write appears in `src/mail/`. The scan verifies all three
   mechanically, in both directions, and this phase adds nothing at all to
   `src/mail/`.

3. **The send is iCloud's.** RFC 6638 defines a scheduling object resource as
   one the server sends scheduling messages for on behalf of the owner of the
   calendar collection. This Worker's outbound byte stream on that path is a
   CalDAV request over HTTPS to the account's resolved CalDAV shard and nothing
   else; the invitation is generated and delivered by iCloud from the stored
   resource, after this Worker's request has already completed.

4. **The content is structurally different from prose.** An invitation carries
   who, when and where — values the USER supplied in the request. It is not a
   paragraph the model wrote in the user's voice, so §2's specific reason does
   not reach it.

5. **PITFALLS #12 still binds, and nothing here relaxes it.** An attendee list
   the user supplies is a request; an attendee list parsed out of a message body
   or an event description is the autonomous-schedule shape that rule forbids.
   Concretely: **no write tool in this project may take an event id, a message
   id, a contact id, or any other identifier as the SOURCE of its attendee
   list.** The attendee list is a caller-supplied array of addresses, full stop.
   A tool that derived one from content this server read would be the breach —
   not the request that carries it.

6. **The safety argument changes shape rather than weakening.** An invitation
   cannot be unsent, so what is protected is that the user sees *who* is being
   told and *what* they are being told BEFORE it goes: CALW-08's naming of every
   recipient, plus the preview gate on any create that carries attendees. That
   is the same instinct §2 encodes, applied to the irreversibility that actually
   exists here.

This reconciliation lives on the safety boundary itself, and not only in a phase
artifact, because a session reading §2 alone would read the calendar write path
as a violation and remove it — and removing it would break a requirement the
developer decided on 2026-08-21 rather than fix a breach.

#### Answering an invitation is not this rule's subject either

Phase 18 adds a tool, `calendar_respond_to_invitation`, that answers an
invitation the user was sent. When iCloud holds the invitation, iCloud then
tells the organiser the answer. That looks like the thing this rule forbids. It
is not. The argument is written down here so nobody has to work it out again.

1. **§2's reason is about prose, and an answer is not prose.** §2 exists because
   a message Claude writes is prose in the user's voice, and a person has to read
   it before it goes. An answer is one of three values: accepted, declined or
   tentative. The user picks it. The model writes no words that reach the
   organiser.

2. **This server still sends no mail.** The write is one conditional PUT of the
   user's own copy of the event. Only the user's own answer on it changes.
   Nothing under `src/mail/` changed in this phase. No submission port was
   opened and no mail library was added. This server never sends the reply
   itself, by any route. D-02 ruled that out.

3. **Where a reply goes out, iCloud sends it.** This was measured with the owner
   on 2026-09-26 and is recorded in `18-UAT.md`. For an invitation iCloud itself
   delivered, iCloud told the organiser. By the time the owner checked the
   organiser's account, a few minutes after the write, it showed the new answer.
   For a copy that reached the calendar some other way, nobody was told. The
   writes went from the owner's terminal straight to iCloud, with no Worker in
   the path, so this is a measurement of iCloud and not of this server. The
   Worker deployed at the time was version
   `14278dbf-7461-4ffb-bcc0-4948691e500d`. Each case was measured once.
   Answering a repeating invitation was not measured. What tells the two cases
   apart is whether iCloud returns a Schedule-Tag for the event. When the
   invitation does not show which case it is, the tool says the organiser may
   be told. It never says nobody will be. This server does not see the reply
   arrive, so the tool says it handed the answer to iCloud, not that it was
   delivered.

4. **PITFALLS #12 still binds.** The tool takes no address of any kind. It finds
   the user's own line by matching the addresses iCloud lists for the account
   that is signed in. It never takes an address from the model, and nobody
   else's answer can be set. The answer comes from the user asking, never from a
   message or an event description that asks for one.

5. **The safety is the preview.** A reply cannot be unsent. So the user sees who
   will be told, and what, before anything is written. The preview names the
   organiser and the answer. The write happens only when `calendar_commit` is
   called with that preview's confirmation. This is the same instinct §2 has,
   applied to the one step here that cannot be taken back.

6. **The exception covers this one tool.** Each of these is a decision on this
   boundary, not a refactor: an address input on this tool, a second way to
   answer an invitation, and answering one date of a repeating invitation.

This lives on the safety boundary, and not only in a phase file, for two
reasons. A session reading §2 alone would see a tool that makes iCloud send a
reply, find no argument for it, and delete it. A session reading this alone
might take it as leave to send replies in general. It is leave for this one
tool, answering the user's own invitation when the user asks.

#### A reply the autonomous layer drafts is not this rule's subject either

Phase 28 lets the server place a draft with nobody asking. The draft is a reply to the sender of a
message that matched one of the user's rules. That looks like the thing this rule forbids. It is
not. The argument is written down here so nobody has to work it out again.

1. **§2's reason still holds.** A person looks before anything leaves. The reply sits in Drafts, and
   this server never sends it.
2. **The words are the user's.** The reply's text is written into a rule the user added through a
   previewed tool. The model writes nothing into it when it is placed. The subject, the threading
   headers and the quoted original are added by the same reply tool a user's own reply goes through.
3. **The write path is the same one.** The job calls the reply tool the user's own Claude calls. No
   second write site exists, and the count rule still sees exactly one.
4. **PITFALLS #12 is bent in one place, on purpose.** That rule forbids a write target taken from
   content a stranger wrote. The reply's one recipient is taken from the message's From line, which a
   stranger wrote. It is allowed for three reasons. It is a draft, and this server never sends it. It
   goes only to the claimed sender: never to the Reply-To address, never to anyone copied, never to
   an address in the text. And From can be forged, so the draft may be addressed to someone other
   than the real sender. The person sees that address before sending.
5. **Nothing else is taken.** No other address in a message becomes a recipient: no attendee list,
   no copy list, no reply-all. One function reads the From address, and the scan counts it.
6. **The exception covers this one job.** Each of these is a decision on this boundary, not a
   refactor: a second address the job reads, a recipient other than From, a copy to anyone, and
   sending the reply.

### 3. One socket importer

`cloudflare:sockets` may be imported by exactly one file: `src/mail/socket.ts`.

Its `connectImap()` takes **no parameters**. Host, port, and transport mode are
literals at the `connect()` call site, so the forbidden state is not merely
rejected at every call site — it is unspeakable. There is no value a caller can
pass that reaches the socket.

Adding a parameter to `connectImap()` is how this ban silently dies: nothing
would fail, the scan would still pass, and the guarantee would be gone. Phases 2
and 4 import through this choke-point, so widening it touches every IMAP call
site in the project. Treat a change to its signature as a decision, not a
refactor.

The scan enforces this as a **count**, not as a prohibition: zero importers is a
violation too. A choke-point that was quietly moved, renamed, or emptied guards
nothing, and that failure is far easier to miss than a duplicate.

**The same one-connection-at-a-time property is defended one layer up as
well.** `src/mail/service.ts` holds two session orchestrators over one private
core. The read one is `withMailSession`, plus `withMailSessionOver` for an
already-open stream. The mutating one is `withMutatingMailbox`, plus
`withMutatingMailboxOver`. The core is not exported, and there is no raw escape
hatch past either orchestrator. Both take the same request gate, so one request
has at most one session open at a time, whichever kind it is. A request can hold
several sessions one after another, never together: a mail tool's own, and then
the sessions of the one recall build step that may follow it, or the page sessions of
one backfill call. One lease can cover up to three of them, one after another. The gate refuses a
second session while the first is open, and allows one after the first has
closed. Making the gate refuse every second session, open or not, would silently
stop the recall build, because a step's refusals are silent. That is a decision,
not a refactor. A concurrent combinator wrapped around
any of them is rejected by the scan, exactly as one wrapped around the socket
open is. The scan also refuses one wrapped around a triage verb, because a list
of moves is worked through one message at a time, in one session.

That rule exists because a fan-out here is genuinely tempting rather than
hypothetical. An account-wide unread sweep and an account-wide search are both
natural things to reach for; both were declined on cost, and the first thing
anyone reaching for either writes is a combinator, because that is what makes N
round trips fast. But every session is a socket. Production allows six
simultaneous connections per Worker invocation and counts KV reads and outbound
fetches against the same six — one of which the OAuth provider has already spent
before any mail code runs. iCloud's own per-account ceiling is lower,
undocumented, and deliberately unmeasured, and exhausting it does not fail
politely: it locks the user out of their own mail in Mail.app on their own
devices. A multi-mailbox operation must be serial.

Two layers, on purpose. The structural one is a request-scoped gate that refuses
a second acquisition at runtime. The detective one is the scan, which refuses it
at commit time and is the cheaper of the two, because nothing has to run.

**A third layer works across requests.** The gate above only sees one request, so it cannot stop
two Claude apps signed in to the same Apple ID from each opening a connection. Each signed-in
person now has one Durable Object. A mail tool call must hold that object's lease before it opens
a connection. A second call that finds the lease held is refused at once with a plain reason. It
is not queued. The lease expires on its own after 30 seconds, so a request that dies part-way
cannot hold it forever.

The lease is added to the gate. It does not replace it. Do not remove the per-request gate because
the object serializes too: a bug in the object would then remove the only runtime check, and
nothing would fail. The object holds a lease, its own stored name, the person's recall ledger,
one sealed autonomy record, the person's rules with their activity and job state, and one alarm.
The alarm's jobs run in a fixed order: autonomy first (does the key still stand?), then the rules
job, then recall's revocation, then recall's expiry. One predicate, `anyJobPending()`, keeps the
alarm, and one helper, `scheduleAlarm`, is the only code that sets or removes it. The alarm never
uses the autonomy key: it reads the grant id and the arming time, and asks the sign-in store. A new
job adds a clause to that predicate; a second condition or a second set is a decision, not a
refactor. It never opens a socket and never imports mail code. Changing either of those is a
decision, not a refactor.
The download route that Phase 29.1 adds opens no socket, takes no lease and reads no sign-in. It only
serves a copy a mail tool already made.

A mail tool call can be followed by one recall build step, in the same request. The step
runs only after the tool's own session has closed and its answer is built, and only when
that answer is not an error. It takes the person's lease itself, once, the same way a tool
does. Under that lease it usually opens one session, and in two rare cases up to three, one
after another. It never runs inside a tool's lease, and never after the answer has
been sent. One seam in `src/mcp/server.ts` applies it, to the mail, recall and change
registrars only. The IMAP diagnostic never runs one. Widening that set, or running a step
anywhere else, is a decision, not a refactor.

The build has one other way to run: the backfill. `mail_recall_backfill` runs only when the
person asks Claude to fill their index, on their own sign-in. It never runs on the autonomy
key, and never from the object's alarm. One call reads up to ten build pages, one after
another. Each page takes the person's lease itself, opens at most three sessions under it,
one after another, and gives it back before the next page. One call opens at most fifteen
sessions in all. A session that could outlive its 30-second lease is refused before its
connection opens. So no two connections to iCloud are ever open at once. It reads only a
folder that is still being built, the first time or again after a reset, and it stops when
the index is built. It skips the minute's pause and the daily page count that ordinary steps
obey, and nothing else. The object grants that only for a folder still being built, and caps
it at a daily page count of its own. More pages a call, a folder that is already built, a
call on the autonomy key, or a call nobody asked for, is a decision, not a refactor.

### 4. Credentials never reach a log or an error

There are no logging calls anywhere under `src/`. Not "no logging of
credentials", and not "not on the credential path" — no logging at all,
anywhere in the source tree. A logging call whose arguments mention the bare
environment object is banned in every scanned directory, `scripts/` and
`test/` included, because that object carries the confirmation key and the R2
key pair and naming none of them is exactly how all of them reach a retained
log. A logging call naming a grant's props object is banned the same way and
for a sharper reason: since the switch to per-person sign-in, that object is
where the actual Apple credential lives.

IMAP's `LOGIN` command carries the password inline in the command stream, so
unlike an HTTP `Authorization` header there is no separately-named field a
redactor could target. A "log the command I am about to send" line leaks the
credential with no secret-named variable anywhere in sight, which is why the
rule has to be the blunt one.

Three habits follow, and all three are already established in `src/`:

- Credentials are consumed by write-only helpers that return nothing. The
  password is held in three places only: the props the sign-in page builds
  once and hands to the OAuth library to encrypt, the props the door gets back
  from it, and a holder private to `src/principal.ts`. None of them is passed to
  `JSON.stringify`, attached to an `Error`, or spread into a response.
- `toErrorCategory()` dispatches on error *type*, never reading `.message` or
  `.stack` from a caught value, and maps to a fixed, closed vocabulary.
- No diagnostic field echoes the last command sent.

#### The "which account" answer holds the whole address, and that is a decision

Phase 12 adds a tool, `account_whoami`, that answers which Apple ID the
connection is signed in as. It returns the WHOLE address. That is LIFE-06,
decided as D4 on 2026-09-21 and REVERSED by the owner on 2026-09-23. It looks
like the thing this rule forbids and it is not, so the argument is recorded here
rather than left to be re-derived.

1. **The address does fall under this rule, and the cost is real.** It is the
   login half of the credential pair, so it belongs with the password and not
   with the ordinary fields of an answer. And a tool response is worse than a log
   line in one respect: it is text the model reads, and may quote back into a
   draft, an event, or a later message. Not one word of that stopped being true on
   2026-09-23. The cost was accepted, not argued away.

2. **What is returned, and to whom.** One address: the account THIS connection is
   signed in as, read off the principal the door built from THIS connection's own
   stored props, and handed back to the person holding that connection. Not the
   owner's address, not another user's, not the one in the Worker secret. The
   password is not in the answer and cannot be, because it is not on the principal
   at all. The tool takes no arguments, so there is no value a caller can supply
   that widens what comes back.

3. **The masked form shipped first, and the mask is why it was reversed.** D4
   chose the mask on 2026-09-21 and it shipped: the first character of the local
   part, three bullets, then the domain. Asked live against the deployed server on
   2026-09-23, that answer made the model report the masked string and then say
   the mask meant it could not confirm the account was that exact one. So the mask
   defeated the tool's only purpose, which is telling a person WHICH account a
   connection is on when they hold more than one Apple ID. A tool that cannot
   answer its one question is not a safety measure, it is a broken tool with a
   safety story attached. The owner judged the mask not worth its cost and chose
   the full address. This paragraph argued the other way until that day, and the
   reversal is recorded rather than the old argument quietly edited into the new
   one, because a boundary whose history is rewritten cannot be audited.

4. **`maskAppleId` stays, and is still the only masking function.** It lost a
   caller, not its job. The owner's grants script still masks, because that
   listing prints one line per connection and is read at a glance rather than
   quoted into anything. Its own table of tests is kept, and so is the
   one-character-local-part edge recorded in its docstring in `src/principal.ts`.
   Deleting the function because one caller left would silently unmask the
   listing, and that is the shape this project's count constraints exist to
   catch: losing a guarantee is quieter than gaining a duplicate of it. A mask
   written inline at any call site is still the breach.

5. **The reversal is scoped to this one tool, and widening is a new decision.** No
   other tool in this project answers with the address it is signed in as. Mail,
   contact and event answers carry the addresses written in that mail or data.
   Those have always been there, and this point is not about them. Adding an
   argument to this one is a decision on this boundary rather than a refactor,
   and so is a second tool that answers with the signed-in address, and so is a
   field on any existing answer that carries it. What was decided on 2026-09-23 is a measured exception for one
   question, not a licence to put addresses into responses generally.

6. **This adds no rule to the list, and no scan rule.** Tests hold it instead,
   and the two claims are now pinned INDEPENDENTLY, which they were not while one
   function served both. A table runs the mask over every row of the address spec,
   in both directions, so an accepted address must come back masked and a refused
   one must come back as bullets. Separately, the real door is driven with two
   different listed grants, and each must get its own address back with no mask in
   the body. Reverting the tool to the mask therefore turns the tool cases red
   while the table stays green, and deleting the table turns the table red while
   the tool cases stay green. Neither claim can carry the other any more.

This reconciliation lives on the safety boundary itself, and not only in a phase
artifact, for two reasons that pull in opposite directions. A session reading § 4
alone would read the tool as a leak and delete it, and deleting it breaks a
requirement the developer decided on 2026-09-21 and settled on 2026-09-23 rather
than fixing a breach. A session reading the reversal alone would read it as
permission to put an address into any response, and it is permission for exactly
one answer to exactly one question.

#### The autonomy key is a credential the server holds, and that is a decision

Phase 27 makes autonomy inherent: part of every sign-in. When a person signs in, this server keeps a
key that can sign in to their mail with nobody present. That looks like the thing this rule forbids.
It is a decision the owner made on 2026-09-23, and made inherent on 2026-09-27. The argument is
written down here so nobody has to work it out again.

1. **What the key is.** It is the refresh token of a second sign-in, made only for autonomy. The
   ordinary sign-in page makes it, from the Apple ID and app password the person just typed, after
   Apple has accepted them. The server keeps the token in that person's own Durable Object. Before
   this, only the person's own apps held a key like this. That is the weakening, and it is real.
2. **Everyone who signs in has one.** There is no opt-in and no switch. The sign-in page says so,
   above the fields, before the person signs in. A person who has not signed in since this shipped
   has no key. They get one at their next sign-in, and never by any other path.
3. **The cost, stated plainly.** Every signed-in person has a sealed key stored here. So a compromise
   of this server reaches every signed-in account at once, not only the people who chose it. Someone
   who can only read this server's storage still gets nothing, because the key is sealed. Someone who
   can run code in this Worker can open every key. What the server does with a key on its own is
   bounded to flag and draft by Phase 28. That bound holds for this server's own code. It does not
   hold for an attacker's code, which could use a key for anything this server's tools can do. Before
   this phase, the same attacker got each person only when that person next signed in or used the
   server. The owner accepted this on 2026-09-27.
4. **The password is stored nowhere new.** It sits inside the autonomy sign-in's locked props, like
   every other sign-in's. No new code reads it. The door is still the one place props are read, and
   the two places a principal is made are still the only two.
5. **What opens it.** The token is sealed with a Worker secret before it is stored, and the seal is
   tied to that person. Reading every store this server has opens nothing, because the secret is in
   no store. What opens a key is the secret, the person's object and the sign-in store, together.
   Only code running in this Worker can read a Worker secret.
6. **How it starts.** Only at the sign-in page, after Apple has accepted the password and the
   ordinary sign-in has succeeded. Never through a tool. One file in `src/` arms it, and the scan
   counts that file: zero is a violation, and so is two. If arming fails, the sign-in still succeeds
   and the person has no key.
7. **How it ends.** It has no timer. It lives exactly as long as the person's ordinary connection.
   When the person holds no ordinary sign-in any more, the object revokes the autonomy sign-in and
   deletes its copy, within a day, and at its next use at the latest. The next sign-in makes a new
   key and revokes the old. The owner's grants script ends it by revoking the person's grants, or the
   autonomy grant alone; the object notices within a day, or at its next use, and deletes its copy
   without retrying. Taking someone off the allow list stops every use before the key is read, but
   does not delete it: a store error looks the same as a removal, and deleting on an error would end
   everyone's key at once. A person can also stop it by deleting their app-specific password at Apple.
   There is no switch on this server.
8. **It never reaches a log, an error or a response.** Its names are in the logging scan that covers
   `test/` and `scripts/` as well as `src/`. No method on the object hands the token or a bearer back
   out.
9. **Widening it is a decision, not a refactor.** Each of these is one: a second way to arm it, a tool
   that can arm it, minting one without an interactive sign-in, letting it outlive the person's
   ordinary connection, storing the token unsealed, handing the token or a bearer out of the object, and letting the key call any tool
   beyond the one check that it works. Phase 28 adds the rule set under its own decision.

#### Saving an attachment hands out a link, and that is a decision

Phase 29.1 adds a tool, `mail_save_attachment`. It lets a person save mail attachments to a folder on
their own computer, from Claude Cowork. This server cannot write to anyone's disk. So it copies each
attachment into storage, under that person's own prefix, and hands back a link. Cowork downloads the
link with the shell of the session that has the person's folder connected. The owner decided this on
2026-09-28.

1. **Only the person, asking now.** The tool runs only through the signed-in door. The autonomous
   layer cannot name it, and the scan refuses the name under `src/agent/`.
2. **One link names one copy.** A link names one stored copy and nothing else. Five minutes after it
   is made, it stops working. The download deletes the copy when it ends.
3. **A link works once in practice, not once for certain.** The first download marks the link spent
   before it sends a byte, and deletes the copy when it ends. A second download from the same place,
   or after the first has finished, is refused. Anything that fetches the link first spends it, a
   person's click included, and so does a download that breaks part-way. The answer then is a new
   link. But the spent mark lives in a key-value store that takes time to reach every Cloudflare
   location. So two downloads from two different places, at almost the same moment, can both get the
   file. A strict version needed a new kind of Durable Object. The owner declined it on 2026-09-28, to
   keep rollback open.
4. **An unused copy outlives its link.** The link dies at five minutes. The copy is deleted the next
   time that person saves anything, when anyone tries the dead link, or by the bucket's daily sweep,
   which can take up to two days.
5. **The link is a password for one file.** Anyone who has it before it is used, and before it
   expires, gets the file. It sits in the conversation. The platform's request log keeps every URL for
   seven days, so the link stays there, dead, for up to seven days. The URL shows no user id.
6. **The link is sealed with a new Worker secret.** The link carries whose copy it is, its name, its
   expiry and its size, sealed with `SAVE_LINK_SEAL_KEY`. Nobody can read them from the URL, or make a
   link, without that secret. It is a new credential. It lives in Cloudflare Secrets, one module reads
   it, and its name is in the logging scan.
7. **The spent mark is keyed by the link, not the person.** The download has no signed-in person, so
   the mark cannot be keyed by user id. It is keyed by a hash of the link, in a store of its own, and
   it holds nothing about the person. The first download writes it. Making a link writes nothing, so a
   new link never waits for the store. `store-key-without-a-user` cannot see that key. One module may
   read the store, and the scan counts it.
8. **The download touches no mail.** The copy is made by one read-only, peeking session, like every
   other read. The download opens no mail connection, takes no lease and reads no sign-in. It serves
   only a copy the tool made.
9. **The file is a stranger's.** The answer says so, and says not to open it. The download is always
   sent as a file to save, never as a page to show. macOS does not mark the saved file as downloaded,
   so it gives no warning when the file is opened.
10. **Widening it is a decision, not a refactor.** Each of these is one: a link that works twice; a
    longer life; a link that names more than one copy; a second way to reach a stored copy; the
    autonomous layer calling the tool; a user id in the URL; a link that is not sealed; saving anywhere
    but the person's own disk.

### 5. Reading mail does not mark it read

Claude reading your mail is not you reading your mail. Read status is a field
the user relies on and MAIL-02 returns it, so a fetch that quietly sets the seen
flag does not merely have a side effect — it corrupts an answer the user asked
for.

There are two halves to this, and it is worth knowing which is which.

The **structural** half is that every read opens its mailbox read-only. That
covers listing, finding, reading and opening mail and its attachments, saving an
attachment, the reads behind a reply draft, a move preview, a draft-delete
preview and a rule preview, the change check, and the recall build. The
diagnostic opens the inbox the same way. The sign-in check, the folder listing
and the drafts write open no mailbox. RFC 3501 says no change to the permanent
state of a mailbox opened that way is allowed, per-user state included. But
iCloud answered that open as read-write when it was probed on 2026-09-27. So
whether iCloud would refuse a change inside such a session has not been
measured. What keeps mail unread is the convention half below: every fetch
peeks, the scan enforces it, and `test/read-path-wire.test.ts` holds the exact
commands every read sends. One
separate path may open a mailbox in the mutating form. Only explicit triage
tools use it, and the subsection below says how it is fenced. Opening a mailbox
in the mutating form anywhere else is a decision, not a refactor.

The **convention** half is that every fetch item uses the peeking form — and
this is the half the scan enforces, because a convention is otherwise something
every future call site has to remember. The page-listing path is what makes it
worth enforcing rather than merely writing down: it touches every message on a
page, so one slip there marks twenty-five messages read in a single call instead
of one. `RFC822` and `RFC822.TEXT` carry the same side effect under a different
name and are banned alongside it; `RFC822.SIZE` and `RFC822.HEADER` fetch no
body, set no flag, and are permitted.

Reading the server's reply is unaffected, and that is why the rule is anchored
on the fetch item rather than on the spelling alone: a peeking fetch comes back
under a key spelled *without* the peek, so `src/mail/service.ts` has to look that
key up. A rule keyed on the spelling would ban reading the answer to the very
command it protects.

#### One path may change a mailbox, and it is not a read path

Phase 20 adds a tool that marks one message read or unread. To do that, it has
to open a mailbox in the form that allows changes. This is the one place that
happens. Phase 21 adds flag and move on the same path. Phase 22 adds one more
verb: moving one draft to Trash.

1. **Which paths are read-only.** Every other mail tool goes through the read
   orchestrator. When it opens a mailbox, it opens it read-only. The sign-in
   check goes through the same orchestrator and opens no mailbox. The diagnostic
   opens the inbox read-only, with the same command.

2. **The one path that is not.** A second orchestrator in `src/mail/service.ts`:
   `withMutatingMailbox`, plus `withMutatingMailboxOver`. It runs over the same
   private core and the same one-per-request gate as the read one. Only
   `src/mail/triage.ts` may use it. That module hands out verbs, never a
   session. Its verbs mark one message read or unread, flag or unflag one
   message, move a list of messages from one folder to another, and move one
   draft from the drafts folder to Trash. Archive and Trash are moves to a
   folder the account itself names. Each verb acts only when the user asks.
   The one exception is the flag: the autonomous job may set it, never clear
   it, on a rule the user wrote (§6). It reaches the verb through the same
   tool, so the fences below still hold.

3. **What this gives up.** Before Phase 20, iCloud itself refused a read-status
   change in every session this server opened. Now that is true only on read
   paths. This trades an absolute for a bounded one, on purpose. Triage cannot
   exist any other way.
   (2026-09-28: that iCloud refused the change was never measured. It answers
   the read-only open as read-write. What held before Phase 20, and still holds
   on read paths, is that every mailbox is opened read-only and every fetch
   peeks. See the structural half above.)

4. **What fences the other path.**
   - One place in the code opens a mailbox in the mutating form, and one module
     may use that path. The scan counts both, and refuses zero as well as two.
   - The mutating session is its own type. The compiler will not let a read
     session stand in for it, or the other way round.
   - The verbs fetch no message body.
   - If a mailbox opens read-only anyway, the verb refuses and says so by name.
   - Each verb checks that the mailbox keeps the one flag it changes. If not,
     it refuses by name and sends nothing.
   - The answer reports what iCloud sent back, not what was asked for.
   - A move copies first. It removes the original only after iCloud's reply
     proves where the copy landed. So a failure part-way leaves the message in
     both folders, and never in neither.
   - The only removal names the one message just copied. The folder-wide form
     is banned by the scan. The copy, the removal mark and the removal each
     have one counted site.
   - Nothing removes mail in place or empties Trash. A message in Trash can be
     moved back.
   - Every move is previewed. The commit acts only on the messages the preview
     named, and only if they are unchanged since.
   - The draft delete acts only on one message in the drafts folder that
     carries the draft flag. Its answers carry this sentence, word for word:
     "This acts only on a draft, in the drafts folder, exactly as you were just shown it. It does not check who wrote the draft."
     It never finds a draft by subject or message id. A draft that changed or
     went away is refused, not searched for.
   - The draft delete's Trash is the folder iCloud marks as Trash. A folder
     that is only named Trash is refused.
   - There is no revise verb. A revision is a new draft from the compose tools,
     then this delete. The server does not check the order. The instructions
     tell the model to write the new draft first. A wrong order loses nothing
     for good, because the old draft is in Trash.

5. **How the read side is proved.** `test/read-path-wire.test.ts` holds the
   exact commands every read sends. They were recorded before the split. Editing
   that file is a decision, not a fix.

6. **What is a decision on this boundary, not a refactor.**
   - A mode argument on either orchestrator.
   - A second place that opens a mailbox in the mutating form.
   - A second module that uses the mutating path.
   - A verb that fetches a message body.
   - A new verb beyond these.
   - A way to remove mail in place, or to empty Trash.
   - A second site for the copy, the removal mark or the removal.
   - Using the draft delete on a message outside the drafts folder, or on one
     without the draft flag.
   - Finding a draft by subject or message id.

### 6. The autonomous layer may flag and may place a draft reply, and nothing else

Autonomy is inherent (Phase 27): every person who signs in holds a key that lets this server reach
their mail with nobody present. For a person who adds rules, this server then acts on their new mail
on its own. For a person with no rules, it does nothing. There are no default or starter rules. It
can do exactly two things: set the flag on a message, and place a draft reply to that message's
sender in the Drafts folder. Nothing else.

The reason is §2's reason, with the person removed. The job reads mail written by strangers, and
nobody is looking when it acts. So the only safe design is one where nothing a stranger writes can
change what the job does.

That is held five ways:

1. **Nothing interprets the mail.** Rules match the sender's address, the sender's domain and words
   in the subject. No model reads the message. The job's own code never reads a body. The reply
   tool it calls reads the message to thread the reply and quote it, as it does for any reply. The
   job reads back only whether the draft was placed.
2. **The answer is two numbers and a word.** The matcher says which rule, which message, and flag or
   draft. The code that acts takes the message from its own list, the words from the rule, and the
   one recipient from the message's From line. No identifier comes out of the matcher.
3. **A draft is a reply to the sender, in the rule's words.** The text is the rule's own. The
   subject is "Re: " and the original subject. The one recipient is the address in the message's
   From line, read through one function. Never the Reply-To address, never the Sender line, never
   anyone copied, never an address in the text. No reply goes to this account's own address, to
   mailing-list mail, or when the From line has no usable address.
4. **From can be forged, and that is accepted, not hidden.** Anyone can put any address in From. So
   a reply may be addressed to someone who did not write the message. Because the reply quotes the
   original, it would also carry the forger's words. It is only a draft. The person sees the address
   before sending, and nothing sends it for them.
5. **The job can only name four tools.** The change check, the flag, the reply tool, and the
   sign-in check, which also tells the job the account's own address. It has no way to name any
   other tool, so it cannot send, delete, move, write a new message, answer an invitation or write
   an event. The scan refuses any other tool name in the object's code.

The job reaches mail only through `/mcp`, like any other request. Each call takes the connection
lease inside the door. The job never takes the lease itself, and its calls go one at a time. The
scan refuses any import of the lease module under `src/agent/`.

An autonomous draft carries no marker. The owner decided that on 2026-09-23. It means a reply
nobody asked for looks like one you wrote. What holds it: the rules are your own and listed back to
you, every rule is previewed before it is added, the job records every reply it places, and nothing
is ever sent.

There is no switch, because autonomy is inherent. The job stops acting for a person when they
remove every rule, when the owner revokes their key or their access, when they leave the allow
list, when their connection ends, or when Apple twice refuses the password itself, the two refusals
at least one wake apart. In that case their next sign-in makes a new key. An iCloud outage, a server
error, or a refusal that does not name the password never counts: the job waits longer between tries
instead, up to a day, and makes no sign-in attempt while it waits. When a person holds no sign-in of
any kind, seen on two checks a day apart, their rules, activity and job state are deleted.

Widening this is a decision, not a refactor. Each of these is one: a third action; a tool the job
can name; a model anywhere in the job; a recipient other than the From address, or a second
address the job reads; a copy to anyone; a reply that is sent; any part of the message put into the
draft beyond what the reply tool already adds (the subject, the threading headers and the quote); a
rule field that sets the cadence; a way to add a rule without the preview; a rule the person did not
add, such as a default or starter rule.

### Enforcement

All six are enforced by `scripts/forbidden-tokens.mjs`, which runs from the
test suite (`test/forbidden-tokens.test.ts`) and from `.husky/pre-commit`. Two
independent gates, because a skipped test run must not disable the ban, and
because a large share of commits here are agent-authored while there is no CI
pipeline to hang a gate on.

The invariant is that every entry sits on that one list behind those same two
gates — pattern rules and count constraints alike, the transport, send,
socket-count, logging, fan-out and read-only rules among them — and that the
list's contents are read from `scripts/forbidden-tokens.mjs` rather than
restated here. This paragraph twice named the newest additions instead, and
twice went stale on the next rule added: naming a fixed pair is a claim with an
expiry date, and the expiry is silent, because nothing fails when prose stops
matching the script. By way of example and not as an inventory,
`append-choke-point-missing` is the arm of §2's write choke-point that fires
when the construction site has been deleted rather than duplicated. Which
entries exist today is a question for the script, not for this file.

Every entry on that list carries a known-violating sample, asserted by a
set-equality check against the rule ids, because a rule that silently matches
nothing is indistinguishable from a rule that was never added. The count
constraints — the socket importer, the two DAV ones and the write among them — carry the
same guarantee through a second set-equality, against the ids their checkers
actually produce when run in both directions, because a constraint whose
"missing" arm can never fire looks exactly like a constraint that was never
added. Every entry also carries a reason longer than a label, because that
string is what the hook prints when it rejects a commit.

**Phase 13 turned a count constraint into a plain ban, and that is a change to
the boundary rather than a refactor, so it is recorded here.** The count
permitted exactly one reader of the account bindings and refused both zero and
two. Then the cutover deleted the thing being read: identity now comes from the
grant somebody signed in with, not from the deployment. Zero became the correct
number of readers, which is the one number the count was written to refuse — so
the count could either become a ban or become a lie about itself. A constraint
whose "missing" arm can never fire looks exactly like a constraint that was
never added, which is the failure the paragraph above describes, and leaving it
in place would have been that failure on purpose. The rule id is deliberately
not named here; which entries exist today is a question for the script.

Phase 5 adds no sixth rule. It extends the `dav-concurrent-request` alternation
with the CalDAV write entry points, because that rule enumerates its entry
points by name and a name omitted from the alternation is invisible to every
other assertion in `test/forbidden-tokens.test.ts` — the set-equality guard
included, which operates at the rule level and not at the alternation level. A
write entry point left out of the alternation is therefore unguarded while
looking exactly like a guarded one, and no assertion in the suite can tell the
two apart.

**Phase 17 added two blanket bans, and "blanket" is the owner's decision rather
than a default, so it is recorded here.** The tokens are the RFC 4791
calendar-creation method this runtime refuses to build, and the DAV library's
collection-creation helper that hardcodes it. Neither carries a `scope`. A
narrower scope — `src/` only — was offered on 2026-09-25 and declined, after the
cost of the wider ban was measured rather than estimated: thirty-eight
occurrences across eight files, most of them prose explaining the very
constraint the rules encode. A file exclusion was refused for the harder reason:
exclusion is all-rules-per-file, so skipping the two test files that carry the
platform finding would have silently dropped their fan-out, logging,
host-literal and read-only coverage as well, and that loss would have been
invisible — nothing fails on the way out.

Six live test sites genuinely need the method string, because they ask the
runtime to build a request carrying it and watch it refuse, which is what keeps
the platform verdict honest rather than remembered. All six were fixed AT THE
SOURCE, by assembling the string from fragments at one module-scope constant per
file, which is what this section already prescribes and what § 1 already does for
the banned transport paths. One entry in the containment gate's request
vocabulary is assembled the same way and for the same reason; deleting it was
refused, because a name removed from that vocabulary makes a future call site
invisible while looking exactly like a guarded one.

The consequence lands on every module added under `src/` from now on, and it is
the same consequence § 2 already states: **describe this method by its role and
never by its name** — "the RFC 4791 calendar-creation method this runtime
refuses to build" — and describe the library helper by role too. A source
comment spelling either one fails the very check it was trying to explain, and
the failure arrives as a pre-commit rejection in the middle of an unrelated
plan, with no obvious cause and a tempting one-character "fix" to the pattern.
Take neither that fix nor an exclusion: the answer is always at the source.

**The recall index fails open, so there is one way to it.** A query to the vector index with no namespace searches everyone's vectors. So one module, `src/recall/index.ts`, may name the index binding. Its read and write paths take the signed-in principal and nothing else. It sets the namespace and a metadata filter from `principal.userId`, and it drops any match that belongs to someone else. The store's two by-id read verbs skip the namespace and are banned under `src/`. Its keep-first write verb is banned in `src/recall/`. Describe all three by role in source comments, never by name. The per-person list of vector ids lives in that person's Durable Object. It is written before a vector is stored and cleared after a vector is deleted, so it always holds every id the index holds. Recall is inherent: every signed-in person's recent mail is indexed, with no switch. Their vectors are destroyed within a day of their access ending. The object checks that on its own alarm, asking about the name it stored for itself, so no caller can choose whose index is destroyed or kept. Changing any of this is a change to the safety boundary, not a refactor.

Recall has two drivers and one model. Exactly one call of the recall build step exists under
`src/`, and exactly one call of the backfill, both in `src/recall/drive.ts`. The step runs
after a person's own mail call. The backfill runs when the person calls
`mail_recall_backfill`. So neither the object's alarm nor the autonomy key can start building
an index without a decision. Only one place outside the object asks for a backfill page, in
`src/recall/sync.ts`, so the minute's pause and the daily page count cannot be skipped from
anywhere else. Exactly one model id exists under `src/`, in
`src/recall/embed.ts`, so no model can join the retrieval loop without a decision. The
exhaustive search's old name is refused anywhere under `src/`, comments included, so an
alias cannot come back. Describe the old name and any other model by role in comments,
never by name. Changing any of this is a decision, not a refactor.

**Phase 27 added four checks and six names for the autonomy key.** The key's
names joined the unscoped logging rule, so they are refused in `src/`,
`scripts/` and `test/`. The arm call is a count with one owner, the sign-in
handler; zero is a violation too. The object's imports are walked to the
bottom at commit time, not only in a test: nothing the object loads at run
time may reach mail, DAV, tool, staging or feed code, the login handler, the
OAuth wiring module or the socket module. Type-only imports the compiler
erases are not followed, the same as the Phase 26 closure test. The library's
helper that decrypts a token's props is banned by name under `src/`, comments
included, so **describe it by role** ("the library's token-unwrapping helper")
in any `src/` comment, exactly as §2 and the Phase 17 paragraph say for the
other banned names. Both Worker configs must bind `SELF` to their own name.

**Phase 29.1 added two counts and two rules for saving attachments, and widened two more.** The
counts: one module may read the spent-mark store and the link seal key, and one file hands requests to
the download route; zero is a violation for each. The rules: the route's module may not import mail,
DAV, tool, agent, recall, sign-in, feed, principal, confirm or change-marker code, and no concurrent
combinator is allowed under `src/save/`. The widenings: the fan-out rule names the save read and the
save loop, and the logging rule that covers `src/`, `scripts/` and `test/` names the seal key.
Describe these by role in source comments.

Changing any of these six is a change to the project's safety boundary, not a
refactor. If one of them is genuinely in the way, say so and get a decision —
do not loosen the pattern list to make a commit go through. Exclusion is by
PATH and never by weakening a pattern: when a rule fires on something
legitimate, the answer is to fix the source or exclude the file, never to make
the rule see less.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

See `ARCHITECTURE.md` at the repository root. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
