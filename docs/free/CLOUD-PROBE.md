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

### Optional private terminal deployment

Only after separate approval for a temporary token, prepare a custom API token
with **Account → Workers Scripts → Edit**, restricted to the approved account,
with the shortest practical expiration. Do not add permissions if deployment
fails. Review the summary before creation. Cloudflare displays the new secret
once: when an assistant must not see it, the account owner completes that final
step without another browser capture, then enters it in their own local terminal:

```sh
python3 scripts/deploy-probe-private.py --account YOUR_APPROVED_ACCOUNT_ID
```

Run the command from the repository. The account ID is not the token. Paste the
token only at the masked prompt, never in the command, a file or a chat. The
wrapper verifies the exact probe configuration and pinned Wrangler version,
rejects non-terminal/unmasked input, excludes inherited debug/proxy/credential
variables, disables Wrangler logs/metrics/error reports, and uses `--env-file`
with the null device to avoid loading project secrets. It gives the token only
to the child process environment and discards child output. Process memory and
environment remain accessible to the OS/user; this is not a secret vault or a
guarantee of memory erasure. A timeout or nonzero result is ambiguous: inspect
the named Worker before retrying, without sharing any token or raw logs.

After `DEPLOIEMENT_REUSSI`, leave the page displaying the secret before asking an
assistant to resume browser inspection. Complete the fixed test and revoke the
named temporary token. The public synthetic test itself needs no token.
`python3 scripts/test-private-deploy.py` checks this wrapper offline, including
a real pseudo-terminal with a known fake token and failure paths. It never
authenticates or invokes Wrangler.

Before running the probe, verify the uploaded module/version, SQLite class and
binding, compatibility date/flags and Free plan. Verify logs/traces are disabled
as configured; dashboard templates may enable logs by default. Open the probe's
root page, click its single run button, and save `/status` after completion.
Inspect Cloudflare's Worker and DO metrics for CPU, failures, duration and SQL
usage. Browser round-trip measurements and fixture-generation/parsing elapsed
times are **not metered CPU**. First/warm means successive calls, not guaranteed
independent cold infrastructure starts. Do not infer a 30-second Free DO CPU
allowance from local success alone.

Keep raw account metrics, identifiers and dashboard evidence private unless
publication is approved. Repository validation summaries contain no credentials,
account identifiers, personal endpoint names or private message content.
Cleanup of the disposable deployment and its recovery history requires the
agreed cleanup action. Do not delete/recreate the namespace to bypass a failed
attempt or quota. Full acceptance still requires the additional application,
OAuth/isolation, AI, staging and separately approved live iCloud checks in
[DEPLOY.md](DEPLOY.md#minimal-cloud-acceptance-protocol).

## Current evidence (2026-10-04)

All 107 stages and the listed stop/concurrency checks passed in local workerd.
TypeScript, the forbidden-token scanner and the 47-tool documentation check pass.
Wrangler dry-run reports 2,546.50 KiB uncompressed / 606.17 KiB gzip.

The probe was deployed to the explicitly authorized test Worker on a dashboard-
verified Free account. The owner created a separately approved, account-scoped,
short-lived token and entered it through the private terminal wrapper. The
assistant did not read the token. After verifying the deployed version, binding,
compatibility flags and disabled logs/traces, the one permitted sequence ran to
completion: **107/107 stages returned HTTP 200**, including both 360-page PDF
extractions, the MIME fixture, 10,000 full-dimensional vectors and both exact
cosine searches. Persisted state is `complete`, with 107 stored results. The
temporary token was then revoked and its absence verified in the dashboard.

This establishes real cloud execution for the fixed synthetic workload, not
full application acceptance, a maximum CPU allowance, unlimited capacity or a
per-operation billing measurement. Raw responses, timing records and platform
metrics remain in the owner's private validation report. The complete product,
OAuth, Workers AI, staging, rules and live iCloud acceptance still require their
separate protocol. Do not recreate the completed namespace to repeat this test.

[CI for the tested code revision](https://github.com/lansbe/icloud-mcp/actions/runs/37244110804)
passed the application and Free suites, all 107 local probe stages, six offline
private-wrapper tests, the deployment build and npm audit (zero vulnerabilities).
