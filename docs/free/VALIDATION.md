# Validation evidence

Environment: local Mac arm64, Node 26.5.0, pinned Wrangler 4.122.0 / workerd, Vitest 4.1.11. Tests use synthetic identities and files. No iCloud login, account creation, secret creation, paid service or billing operation was performed. An explicitly authorized test Worker placeholder was subsequently created on the verified Free account; the application and cloud probe are not deployed. See [CLOUD-PROBE.md](CLOUD-PROBE.md) for the exact state and local probe checks.

## Automated checks

- `npm run check`: TypeScript, original forbidden-token and ownership checks, exact 47-tool inventory, full upstream suite and Free integration suite.
- Upstream baseline: 6,171 passed, one failed only because the checkout path contained `icloud-mcp`. The canary test now checks the service hostname `icloud.com`, while its password, address and forbidden-command assertions remain.
- Full final suite: **6,176 tests passed in 111 files**. The Free suite adds **20 passing tests in 4 files**, covering maximum-size blobs, signed upload/tamper/expiry, transactional races, exact vector ranking and 10,000-vector capacity, real local OAuth/PKCE exchange, concurrent identity isolation, slow-body recovery and revocation-budget coverage.
- `npm run build:free`: bundle builds with only five SQLite DO classes, three KV namespaces, AI, SELF and the existing rate limiters. Measured build: approximately 5,036 KiB uncompressed / 1,124 KiB gzip.
- `npm audit --audit-level=high`: zero reported vulnerabilities on 2026-10-04. Compatible transitive updates and patched Vitest were applied; undici 7.29.1 and sharp 0.35.4 are pinned overrides. No audit bypass or forced major platform upgrade.
- CI runs the same local check/build/audit with Node 22.18 and no cloud secrets or deployment step. Its first Linux run passed 6,169 tests and hit seven 5-second deadlines in repeated whole-repository scans. The static project now allows 30 seconds per test; Worker deadlines and explicit scanner complexity assertions are unchanged.
- A later Linux run of `2397da6` passed 6,175/6,176 tests but measured 2,115 ms for the 600-page PDF probe against its unchanged 2,000 ms assertion. `npm test` now runs all 29 timing/protocol probes after the remaining suite, so they do not compete with other test files for CPU. No threshold, PDF limit or production deadline was raised. The 29 probes pass locally in this isolated mode; this remains elapsed local-runtime evidence, not cloud CPU evidence.

## Local profiling

`npm run bench:free` builds a separate **non-deployable** synthetic harness. Outbound network is denied; OAuth fixtures are ephemeral local grants. The production deployment validator only allows `src/index.ts`. The harness restores the canonical Host header replaced by Miniflare's loopback transport; production host validation is not relaxed.

V8 `Profiler` samples at 100 microseconds. The estimate below sums sample time deltas excluding `(idle)` and `(root)`; it includes runtime/profiler overhead and may include `(program)` intervals. It is an estimate of local active sampling, **not exact request CPU**, not a platform CPU measurement, and not an inference that elapsed time equals CPU. Sub-millisecond/short measurements and single runs are noisy. Each first/warm pair is successive calls in one runtime, not independent cold starts of Cloudflare infrastructure.

| Operation | Elapsed ms | Active sampling estimate ms |
| --- | ---: | ---: |
| discovery-first-request | 12.09 | 10.62 |
| discovery-warm | 1.77 | 1.51 |
| oauth-bearer-and-whoami-first | 19.55 | 18.86 |
| oauth-bearer-and-whoami-warm | 9.08 | 8.64 |
| 47-tool-schemas-first | 7.94 | 7.50 |
| 47-tool-schemas-warm | 11.77 | 11.34 |
| mime-first | 173.18 | 103.92 |
| mime-warm | 166.44 | 89.11 |
| pdf-small-first | 39.25 | 30.38 |
| pdf-small-warm | 2.87 | 2.80 |
| pdf-large-first | 455.77 | 455.51 |
| pdf-large-warm | 440.09 | 438.91 |
| cosine-10000-first | 37.05 | 36.74 |
| cosine-10000-warm | 35.98 | 35.73 |

Runtime-ready elapsed: 201.32 ms, including simulator startup and fixture/module work. This is **not** the deployment startup metric. MIME fixture: about 400 kB of synthetic HTML. PDF fixture: 360 pages, under the retained 2 MiB parser ceiling. All 47 schemas produce about 56.6 kB. Exact cosine scans all 10,000 1024-dimensional vectors through the real SQLite store. No production heap peak or CPU accounting is claimed. Aggregate raw measurements are generated in ignored `benchmark.local.json`; no grant/token is logged or committed.

The upstream PDF probe's old 814 ms initialization and 640 ms large-document results are local elapsed observations only. They are not used as production CPU evidence.

## Independent targeted review

A separate reviewer inspected global-object identity, storage isolation, one-time use and the scanner exceptions. Four concrete findings were addressed:

1. Four incomplete anonymous bodies could occupy every application slot: bounded read with an absolute ten-second deadline, cancellation and recovery tests added.
2. Refresh could consume the shared OAuth budget and block final revocation: independent bounded cleanup reserve, tested after both ordinary budgets exhaust.
3. Scanner exception accepted prefixed receivers such as `request.env`: exact receiver boundary and counterexamples for all four named service exceptions added.
4. `observability.enabled=false` could be overridden by explicit logs or tail consumers: deployment validation refuses these configurations, with regression tests.

No direct cross-user disclosure was found in the reviewed public paths. This targeted review is not a comprehensive security certification. Logical ownership checks, platform encryption, recovery-copy retention and coordinated restore requirements are documented in [ARCHITECTURE.md](ARCHITECTURE.md).

## Remaining acceptance blockers

An existing, explicitly approved Cloudflare **Free** account is needed to prove actual edge/DO CPU, startup, storage quotas and included AI behavior. A separately approved synthetic iCloud test account and user-entered app-specific password are needed for live IMAP/DAV interoperability. The precise minimal protocol and permissions are in [DEPLOY.md](DEPLOY.md#minimal-cloud-acceptance-protocol). Neither gap can be closed by local simulation, and neither authorizes an upgrade, new account, payment or real secret handling.
