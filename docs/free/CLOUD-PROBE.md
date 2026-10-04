# Bounded synthetic cloud probe

This probe is separate from the application and from `scripts/bench/worker.ts`.
The latter is a **local-only** authentication harness and must never be deployed.
The probe does not establish full application acceptance by itself.

## Fixed workload and stop conditions

`scripts/cloud-probe/worker.ts` uses the actual MIME parser, PDF dependency and
`SemanticStore` implementation. It accepts no documents, credentials, workload
parameters, reset operation, callback URL or outbound service. One SQLite object,
always named `synthetic-once-v1`, persists one 107-step sequence:

1. One-page synthetic PDF, first and warm extraction.
2. 360-page synthetic PDF, first and warm extraction, below 2 MiB.
3. Approximately 400 kB of synthetic MIME HTML.
4. One hundred batches of 100 full 1024-dimensional vectors.
5. Two exact cosine searches over those 10,000 vectors.

An atomic SQLite transaction marks each attempt `running` and advances its
counter **before** the work. Storage synchronization precedes heavy computation.
Only successful completion unlocks the next step. A failure, lost isolate while
running, or completed sequence cannot be retried through the public interface.
Concurrent calls may complete distinct subsequent steps, but cannot repeat one.
The namespace must not be recreated or rolled back to restart a test without a
fresh decision about quotas and authorization.

The HTML button executes at most 107 empty same-origin POSTs. The edge rejects
query parameters, bodies, chunked uploads, unknown routes and cross-origin step
requests. The DO does not read request bodies. `/status` returns only aggregate
synthetic results. There are no real identities, tokens or message contents.

This finite workload needs approximately 40 MiB of raw vector storage plus
SQLite overhead. Its 10,000 inserts and their indexes, per-batch counters and
progress records are conservatively below 50,000 SQL row writes; the two scans
and bookkeeping are below 100,000 row reads. These are design bounds, **not
observed Cloudflare billing counters**. Capture the real counters before/after.
There is no recurring alarm or background job. Ordinary public HTTP requests
and rejected/status DO calls can still consume request quotas: finite heavy
work does not make an Internet endpoint immune to request flooding.

## Reproducible local checks

```
npm run test:probe
npm run typecheck
npx wrangler deploy --dry-run --config wrangler.probe.jsonc
```

`test:probe` blocks external network access, builds the actual deployable bundle
at `dist/cloud-probe/worker.mjs`, and tests malformed inputs, same-origin checks,
concurrent reservation, the entire sequence, completion, persisted running and
failed states, and absence of a reset endpoint. Its separate instrumented
`test-worker.mjs` is **never deployable**. The source is covered by TypeScript;
CI runs the local probe without cloud secrets or deployments.

## Authorized deployment procedure

Obtain specific approval for the named Free account, Worker and SQLite storage
before deployment. Inspect the existing Worker list and do not overwrite an
unrelated namesake. `wrangler.probe.jsonc` names `icloud-mcp`, with exactly one
SQLite export/binding, no secrets, AI, KV, R2, Vectorize, cron or paid CPU setting.
It is a test configuration, not the product configuration.

Prefer the approved existing dashboard session. If the dashboard cannot create
the class or upload the module, stop and explain the exact missing capability.
Do not silently authorize Wrangler, connect a Git provider, create a token,
upgrade a plan, or switch to a personal browser. The local dry-run does not
authenticate or deploy anything. A Hello World placeholder is not the probe.

Before running the probe, verify the uploaded module/version, SQLite class and
binding, compatibility date/flags and Free plan. Verify logs/traces are disabled
as configured; dashboard templates may enable logs by default. Open the probe's
root page, click its single run button, and save `/status` after completion.
Inspect Cloudflare's Worker and DO metrics for CPU, failures, duration and SQL
usage. Browser round-trip measurements and fixture-generation/parsing elapsed
times are **not metered CPU**. First/warm means successive calls, not guaranteed
independent cold infrastructure starts. Do not infer a 30-second Free DO CPU
allowance from local success alone.

Keep results and account identifiers private unless publication is approved.
Cleanup of the disposable deployment and its recovery history requires the
agreed cleanup action. Do not delete/recreate the namespace to bypass a failed
attempt or quota. Full acceptance still requires the additional application,
OAuth/isolation, AI, staging and separately approved live iCloud checks in
[DEPLOY.md](DEPLOY.md#minimal-cloud-acceptance-protocol).

## Current evidence (2026-10-04)

All 107 stages and the listed stop/concurrency checks passed in local workerd.
TypeScript, the forbidden-token scanner and the 47-tool documentation check pass.
Wrangler dry-run reports 2,546.50 KiB uncompressed / 606.17 KiB gzip.

The explicitly authorized `icloud-mcp` placeholder Worker was created through
the integrated browser after verifying no existing projects and an active Free
plan at $0. The browser/tool connection failed and was restored using the
documented browser-session reset. The existing Worker was confirmed unchanged.
The editor's upload command did not produce a file chooser through either
documented browser interaction path. The dashboard's DO binding dialog lists
only existing namespaces (zero options); the DO account page has no namespace
creation control. Deployment through Wrangler/API therefore needs a separately
approved authentication route, or a user-operated deployment. None was started.
**No cloud PDF/vector execution or platform CPU measurement is claimed.** Resume
from the existing Worker; do not create it again.
