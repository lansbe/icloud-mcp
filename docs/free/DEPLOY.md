# Deploying the Free profile

Status: locally tested; no live deployment or iCloud connection performed. Follow this profile instead of the upstream R2/Paid instructions. This is a fresh-install path; it does not migrate existing users or copy a live upstream datastore.

## Local verification without an account

Use Node >=22.18. All automatic tests use synthetic accounts. They disable remote bindings. Never run `wrangler dev` with real credentials: AI bindings can be remote unless explicitly disabled by the test harness.

```sh
npm ci
cp wrangler.jsonc.example wrangler.jsonc
npm run prepare:free
npm run check
npm run build:free
npm run bench:free
```

`wrangler.jsonc` supports the unchanged legacy test suite only. The ignored `wrangler.free.jsonc` is the deployable configuration. `build:free` is a local dry-run; it creates no resources. `bench:free` blocks outbound network, generates fake PDFs and a fake OAuth grant inside an ephemeral local runtime, and prints aggregate timings only. Its CPU samples are not production billing measurements. See [VALIDATION.md](VALIDATION.md).

## Approval required before cloud actions

For this development task, the user has authorized GitHub fork/commits but has **not** authorized Cloudflare provisioning, deployment, secret creation, permission changes or iCloud login. The following commands are a reviewable runbook, not actions already taken. Stop if Cloudflare asks for payment, an upgrade, a new token, expanded permissions or a new account. Existing CLI authorization may be used only after the user approves the named account and intended cloud operations. Never inspect credential files or print tokens.

The minimum approval is: use the user's identified existing **Workers Free** account; create three KV namespaces and this Worker's five SQLite DO classes; deploy only this fork with synthetic data first; create the four named application secrets; use included Workers AI with a tiny synthetic embedding. No R2, Vectorize, payment or third-party AI account is needed. An existing `workers.dev` subdomain avoids purchasing a domain. The dashboard must show Workers Free and no required billing checkout for these operations. The CLI acknowledgement is not an account-plan API check.

After approval, inspect the selected account in the dashboard and run `npx wrangler whoami` to confirm its identity. Do not dump tokens. Create the three namespaces with the pinned Wrangler:

```sh
npx wrangler kv namespace create OAUTH_KV --config wrangler.free.jsonc
npx wrangler kv namespace create DAV_CACHE --config wrangler.free.jsonc
npx wrangler kv namespace create ALLOW_LIST_KV --config wrangler.free.jsonc
```

Fill their distinct IDs in `wrangler.free.jsonc`. Keep its name and `SELF.service` equal. For a free hostname, set `workers_dev: true`, `routes: []`, and `vars.PUBLIC_HOSTNAME` to `icloud-mcp-free.<your-existing-subdomain>.workers.dev`. Keep `preview_urls: false`. Alternatively, use one custom domain already owned by the user, with `workers_dev: false`; do not buy a domain for this task. Set the explicit allow list in the ignored config. Never commit real IDs, addresses or secrets.

The application requires `CONFIRM_SECRET` and `SAVE_LINK_SEAL_KEY`, plus `AUTONOMY_CLIENT_SECRET` and `AUTONOMY_SEAL_KEY`. The last pair are set by the existing autonomy setup command, which also creates its OAuth client. The save seal key and autonomy seal key must each be exactly 32 random bytes encoded as base64url; CONFIRM_SECRET must be a strong unpredictable value. Generate/store values only after separate authorization, privately through secure interactive input; never through command-line values or committed `.dev.vars`. Setting a Worker secret can itself publish a Worker version.

```sh
npx wrangler secret put CONFIRM_SECRET --config wrangler.free.jsonc
npx wrangler secret put SAVE_LINK_SEAL_KEY --config wrangler.free.jsonc
npm run deploy -- --confirm-free-plan
ICLOUD_PROFILE=free node scripts/grants.mjs autonomy-setup
```

The last command previews setup. Its `--yes` form creates the autonomy client and two secrets and therefore needs explicit approval. The Free profile selector applies to **every** remote Wrangler call made by `grants.mjs`, including secret puts. Never run it without `ICLOUD_PROFILE=free` against a Free deployment. Grant inspection/revocation/housekeeping use the same selector:

```sh
ICLOUD_PROFILE=free node scripts/grants.mjs list
ICLOUD_PROFILE=free node scripts/grants.mjs revoke --address '<approved-address>'
```

Review before adding `--yes`. Removing an address from the allow list blocks future logins; revoking existing grants is a separate required step. On failure, stop and diagnose; do not switch to the legacy config to get a deployment through.

## Minimal cloud acceptance protocol

1. Record account identity and verified Free plan, release SHA, compatibility date, bindings and absence of R2/Vectorize/paid CPU overrides. Keep account-specific details private. Confirm available remaining account quotas before the probe.
2. Deploy the production entrypoint. Check OAuth discovery and a 401 for anonymous `/mcp`; wrong host must fail. Confirm startup and edge CPU in Cloudflare's metrics. **Do not deploy the local benchmark entrypoint**, which intentionally permits synthetic setup.
3. On a separate explicitly approved disposable probe Worker, with no real secrets or real mailbox, exercise the same DO classes using the local synthetic PDF/MIME/vector fixtures. Capture platform CPU and wall time separately for cold/warm OAuth, all 47 schemas, 2 MiB PDF, MIME, 20 MiB save and 10,000-vector cosine query. Check edge <=10 ms, startup <=1 s and actual Free DO CPU behavior. Request-volume, SQL reads/writes and duration must fit the plan. A rejection or need for Paid is a blocker, not permission to subscribe.
4. Probe a tiny bge-m3 embedding using included AI; record neuron change. Verify synthetic semantic ranking, isolation of two test principals, signed upload expiry/replay and concurrent one-time claims. Delete the disposable probe after explicitly approved cleanup; record any retained recovery history.
5. Only with separate permission, the user signs in via the browser using an approved test Apple ID and enters its app-specific password themselves. Do not ask the assistant to read it from storage. Start with diagnostics, then list/search/read designated synthetic mail, MIME and PDF attachments, calendar and contacts. Check exact and semantic search independently.
6. With explicit approval for test mutations, stage/download synthetic files, create only drafts, preview+commit a move and synthetic DAV/contact changes, and run a flag/draft-only rule on designated mail. Verify cleanup through the same preview/commit paths. No SMTP exists and nothing is sent. Confirm revocation ends access and no other principal can read test objects.

Release acceptance remains blocked until these cloud checks establish actual Free CPU/startup/quotas and the approved iCloud checks establish protocol behavior against Apple. Local tests prove implementation behavior; they cannot establish account eligibility or real service availability.
