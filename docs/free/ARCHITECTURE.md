# Workers Free architecture and limits

This fork targets Workers Free. Local implementation and tests are complete; production eligibility and CPU enforcement still require a separately authorized probe on an existing Free account. No account, billing setup, secret or deployed resource was created during development. Do not interpret a local test or `--confirm-free-plan` as verification of the account's billing plan.

## Execution

The edge forwards the original request to the fixed `FreeApplication` SQLite Durable Object. The existing OAuth provider authenticates it there, then the existing MCP handler creates a fresh principal and server. Each invocation gets a new execution context; a global object never holds authenticated props between requests. The per-person `UserAgent` remains named from the authenticated principal. Its leases, encrypted autonomy grant, alarms, cursor and rules implementation are retained.

The application admits four concurrent fetch handlers. Bodies have a ten-second absolute read deadline; OAuth bodies are limited to 64 KiB and MCP requests to 16 MiB. An attachment upload remains 4 MiB. This is an additional bounded-volume constraint, not a changed tool schema. Slow bodies are cancelled and slots released. Admission is not fair scheduling: denial of service can still exhaust shared Free capacity.

`BlobVault`, `SemanticStore` and `FreeBudget` have fixed deployment-wide names. No request parameter chooses one. They expose only internal RPC; public routes must first pass the existing owner checks or validate a signed capability. Sharing physical tables is **logical isolation**, not a separate database or encryption key per person.

## Attachments without R2

The Free profile declares no R2 binding or S3 credential. `BlobVault` stores 512 KiB chunks in SQLite, below the 2 MB row limit. Atomic reservations cap active and pending blobs together at 256 MiB and 512 objects. Files of 20 MiB can be saved; staging remains 4 MiB/file, inline input 256 KiB, and drafts at most three attachments. Streaming reads retain one chunk at a time. Partial uploads expire after 15 minutes and complete files after 24 hours, with an alarm deleting expired active rows.

Presigned URLs now point to the same origin. They retain the caller-facing PUT contract, including `content-length`, `content-type`, and `x-amz-meta-filename`. A domain-separated HMAC binds key, filename, size, type and expiry; an atomic claim precedes ingestion. Upload, preview/commit and download capabilities are single-use under concurrency. A failed claimed operation stays consumed; request a fresh preview or link. No automatic retry of a mutation occurs.

## Semantic search without Vectorize

Workers AI still runs **`@cf/baai/bge-m3`**, with full 1024-dimensional embeddings and the existing text preparation. SQLite stores Float32 vectors and the same reference/subject metadata. An owner-indexed cursor computes exact cosine similarity, retains at most 50 results, and uses deterministic ID ordering for exact ties. The existing minimum score, per-user namespace check and result-owner validation remain. This changes the nearest-neighbour engine from approximate to exact; it is not keyword search or a model substitution.

The existing 10,000 entries/person and 90-day recall retention are retained. A deployment can hold 40,000 entries total; this is a shared capacity, not a fixed four-user limit. Metadata is capped at 8 KiB/vector. The worst-case raw vector-plus-metadata payload is under 500 MiB; SQLite indexes and provider bookkeeping also consume storage. There is no full-index array in memory. Insertion uses transactional counters, not a scan of all prior rows. At 10,000 entries one search reads about 10,000 vector rows plus index work. A 200-search daily admission cap leaves room below the provider's five-million-row read allowance; other operations and other applications in the account consume the same allowance.

## Quotas and capacity

Official sources checked 2026-10-04. Recheck before deploying; account quotas are shared with other applications.

| Primitive | Published Free allowance | Consequence |
| --- | --- | --- |
| [Workers](https://developers.cloudflare.com/workers/platform/limits/) | 100,000 requests/day; 10 ms CPU/request; 128 MB; 1 second startup; current bundle limit 64 MiB uncompressed | Edge forwards; expensive OAuth/schema/MIME/PDF work executes in the DO. Local build size does not prove production startup or CPU. |
| [Durable Objects](https://developers.cloudflare.com/durable-objects/platform/pricing/) | SQLite on Free; 100,000 requests/day; 13,000 GB-s/day; 5M rows read/day; 100,000 written/day; 5 GB/account | Free quota exhaustion makes operations fail. Duration includes time waiting on I/O, unlike CPU; 13,000 GB-s is about 28.9 object-hours at 128 MB, summed across objects. |
| [DO limits](https://developers.cloudflare.com/durable-objects/platform/limits/) and [FAQ](https://developers.cloudflare.com/durable-objects/reference/faq/) | Default invocation CPU 30 seconds, maximum configurable 5 minutes; 2 MB row. FAQ states 1 GB/object on Free while the limits table is less specific. | No paid CPU override is set. We remain below 1 GB/object. **Actual Free CPU enforcement must be checked in the cloud**: documentation also refers to general Workers CPU limits. |
| [Workers AI](https://developers.cloudflare.com/workers-ai/platform/pricing/) | 10,000 neurons/day on Free | Same model, no external AI API key. Provider quota is authoritative; 2M UTF-8 input bytes/day is an application guard, not an exact neuron meter. |
| [Workers KV](https://developers.cloudflare.com/kv/platform/limits/) | 100,000 reads/day; 1,000 writes/day; 1 GB; one write/second to the same key | Three separate namespaces: OAuth, DAV cache, allow list. Provider hard limits remain; request counters do not meter every KV operation. |
| [Vectorize](https://developers.cloudflare.com/vectorize/platform/pricing/) | 5M stored and 30M queried dimensions/month | Not used in Free profile: only 4,882 complete 1024d vectors fit globally, less than upstream's 10,000/person. |

Application budgets reset at UTC midnight: 2,000 ordinary requests/day, 128 OAuth registration/login/token operations/day, 256 separately reserved token revocations/day, 2M embedding input bytes/day, and 200 semantic searches/day. Counters are atomic; failed operations consume reservations. They are deliberately conservative admission bounds, not substitutes for provider metering or guarantees against every platform limit. On Paid the same primitives can incur charges: **this configuration cannot turn a Paid account into a Free account**.

Each autonomous session requires a refresh, plus a separately budgeted revocation. One continuously active 15-minute schedule uses at least 96 refreshes/day; multiple people share the 128-operation budget with interactive sessions and login. KV writes, AI usage, per-user session pacing and DO duration can constrain volume earlier. Rules remain available, but continuous 15-minute operation for an arbitrary number of people is not promised. Quota failures pause progress and require capacity/reset, never a paid upgrade or silent switch to weaker search.

## Confidentiality, retention and recovery

[DO data security](https://developers.cloudflare.com/durable-objects/reference/data-security/) documents automatic AES-256/LUKS encryption at rest, including metadata, Cloudflare-managed keys, and TLS between Workers and DOs. [KV data security](https://developers.cloudflare.com/kv/reference/data-security/) documents encryption at rest and TLS as well. Blobs, vectors and subject metadata have no additional application encryption or per-person key; authorized application code and Cloudflare's storage layer can process plaintext. Embeddings can reveal information and are treated as sensitive. This is not end-to-end encryption. Existing OAuth grant encryption and autonomy sealing are retained.

The upstream R2 lifecycle removed active attachment objects in about two days. Here active blobs expire within 24 hours, but [SQLite point-in-time recovery](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/#point-in-time-recovery) may preserve recovery copies for 30 days. Recall's 90-day deletion likewise means active records, not proof of erasure from recovery history. No cryptographic erasure is claimed. Local `.wrangler` test stores have no platform encryption guarantee and contain synthetic data only.

Never restore `FreeBudget` alone: that could resurrect spent links. After an authorized disaster recovery, keep public access disabled, invalidate all upload/confirmation/download capabilities by rotating their signing secrets, and wait at least the maximum capability lifetime before reopening. Reconcile vector counts with the restored rows and reset/rebuild each person's recall ledger and vector index together; do not independently rewind one. Grant/rule recovery needs the upstream revocation procedure. Secret rotation, restore and deletion are operator actions requiring explicit approval in this development task.

Invocation logging, tails and explicit logs/traces are refused by the Free deployment validator because URLs contain bearer capabilities. The old profile remains as a compatibility/test fixture, but `npm run deploy` uses only the Free config.
