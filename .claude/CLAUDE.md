<!-- GSD:project-start source:PROJECT.md -->

## Project

**iCloud MCP**

An MCP server hosted on Cloudflare Workers that proxies iCloud Mail (IMAP), Calendar (CalDAV), and Contacts (CardDAV), giving Claude native tool access to the Apple ecosystem. Claude can read and search mail, draft replies into the iCloud Drafts folder, read and manage calendar events, and look up contacts — all without credentials ever leaving the server.

Built for a single user (Russell) against one Apple ID. The immediate driver is a job search: drafting thank-you notes, replying to recruiters, and finding calendar slots. The longer arc is moving Claude from "a thing you paste context into" toward a genuine personal assistant.

**Core Value:** Claude can read your real iCloud mail and calendar, and prepare real work against them — a draft sitting in your Drafts folder, an event on your calendar — without you ever copying and pasting.

### Constraints

- **Tech stack**: Cloudflare Workers, TypeScript, MCP TypeScript SDK — consistency with the existing `code-assist` and `engram` servers.
- **Runtime**: Workers has no persistent connections and a bounded CPU/wall-clock budget per request. IMAP sessions must be established and torn down within a single request, or pooled through Durable Objects.
- **Transport**: IMAP must go over the Workers-native TCP Sockets API (`connect()` from `cloudflare:sockets`) with implicit TLS on port 993. No intermediary bridge.
- **Security**: Credentials exist only in Cloudflare Secrets. They must never appear in tool responses, error messages, or logs. The MCP endpoint must be authenticated — it reaches real personal mail.
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
- Concurrent open sockets count toward a per-Worker connection limit (exact numeric ceiling not published on this page; not a concern at single-user IMAP-then-close scale).

## Recommended Stack

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
| `@cloudflare/workers-oauth-provider` with a minimal first-party auth handler | Static bearer token in a `fetch` guard | If OAuth 2.1 compliance is deliberately deprioritized in favor of the simplest possible implementation — acceptable technically for a single-user server never exposed to third-party MCP clients, but forfeits the token lifecycle/revocation properties `PROJECT.md` already committed to. |
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

These five are safety boundaries, not style preferences. Each one states its
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

A draft reaches the iCloud Drafts folder via IMAP `APPEND`. That is the entire
write path, and it is deliberately the entire write path.

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

Nothing is given up here either. There is no point on this project's roadmap
where a second write path is the answer, and a second one would be a second
thing this project can do to the user's account, arriving without a decision.

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
   mail-sending library is linked, and no second write construction site appears
   in `src/mail/`. The scan verifies all three mechanically, in both directions,
   and this phase adds nothing at all to `src/mail/`.

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

**The same one-connection-per-request property is defended one layer up as
well.** `src/mail/service.ts` holds exactly one session orchestrator —
`withMailSession`, plus `withMailSessionOver` for an already-open stream — and
there is no raw escape hatch past it. A concurrent combinator wrapped around
either is rejected by the scan, exactly as one wrapped around the socket open is.

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

### 4. Credentials never reach a log or an error

There are no logging calls anywhere under `src/`. Not "no logging of
credentials", and not "not on the credential path" — no logging at all,
anywhere in the source tree. A logging call whose arguments mention the bare
environment object is banned in every scanned directory, `scripts/` and
`test/` included, because that object carries `AUTH_SECRET`, `APPLE_ID`, and
`APPLE_APP_PASSWORD` and naming none of them is exactly how all three reach a
retained log.

IMAP's `LOGIN` command carries the password inline in the command stream, so
unlike an HTTP `Authorization` header there is no separately-named field a
redactor could target. A "log the command I am about to send" line leaks the
credential with no secret-named variable anywhere in sight, which is why the
rule has to be the blunt one.

Three habits follow, and all three are already established in `src/`:

- Credentials are consumed by write-only helpers that return nothing, so no
  object holding a password is ever constructed, and nothing exists to
  `JSON.stringify`, attach to an `Error`, or spread into a response.
- `toErrorCategory()` dispatches on error *type*, never reading `.message` or
  `.stack` from a caught value, and maps to a fixed four-value vocabulary.
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
   other tool in this project returns an address. Adding an argument to this one
   is a decision on this boundary rather than a refactor, and so is a second tool
   that answers with an address, and so is a field on any existing answer that
   carries one. What was decided on 2026-09-23 is a measured exception for one
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

### 5. Reading mail does not mark it read

Claude reading your mail is not you reading your mail. Read status is a field
the user relies on and MAIL-02 returns it, so a fetch that quietly sets the seen
flag does not merely have a side effect — it corrupts an answer the user asked
for.

There are two halves to this, and it is worth knowing which is which.

The **structural** half is that every mailbox is opened read-only. RFC 3501 is
explicit that no change to the permanent state of a mailbox opened that way is
permitted, per-user state included, so the server refuses the mutation for the
whole session no matter what an individual command asks for. Opening a mailbox
in the mutating form instead is a decision, not a refactor.

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

### Enforcement

All five are enforced by `scripts/forbidden-tokens.mjs`, which runs from the
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
constraints — the socket importer, the two DAV ones, and the write — carry the
same guarantee through a second set-equality, against the ids their checkers
actually produce when run in both directions, because a constraint whose
"missing" arm can never fire looks exactly like a constraint that was never
added. Every entry also carries a reason longer than a label, because that
string is what the hook prints when it rejects a commit.

Phase 5 adds no sixth rule. It extends the `dav-concurrent-request` alternation
with the CalDAV write entry points, because that rule enumerates its entry
points by name and a name omitted from the alternation is invisible to every
other assertion in `test/forbidden-tokens.test.ts` — the set-equality guard
included, which operates at the rule level and not at the alternation level. A
write entry point left out of the alternation is therefore unguarded while
looking exactly like a guarded one, and no assertion in the suite can tell the
two apart.

Changing any of these five is a change to the project's safety boundary, not a
refactor. If one of them is genuinely in the way, say so and get a decision —
do not loosen the pattern list to make a commit go through. Exclusion is by
PATH and never by weakening a pattern: when a rule fires on something
legitimate, the answer is to fix the source or exclude the file, never to make
the rule see less.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
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
