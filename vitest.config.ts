// Test wiring (D-03, D-09): tests execute inside the real workerd runtime,
// not a Node mock, so D-03's in-process ordering proof runs the actual Worker.
//
// The pool is registered as a Vite *plugin*. The rationale for this import
// shape — and for the earlier API it replaces — is recorded in
// .planning/phases/01-foundation-imap-connectivity-proof/01-01-SUMMARY.md
// rather than here, because this file is grepped for the superseded name.
//
// Two projects, because this suite has two genuinely different needs and
// Vitest 4 does not inherit root plugins into inline projects (that changes in
// 5, so the plugin is declared inside the project that needs it rather than at
// the root where it would silently apply to neither):
//
//   workers — everything that exercises Worker behaviour. Real workerd.
//   static  — the forbidden-token scan, which reads the repository off disk.
//             A Workers isolate has no filesystem, so this cannot run in the
//             pool: `readFileSync` there resolves against a virtual filesystem
//             holding only the bundle, and every repo path is a miss.
//
// The split is deliberately narrow. Anything that is not filesystem-bound
// belongs in the workers project, where the runtime is the real one.
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/** The only tests that read files off disk -- the repository tree for the
 *  forbidden-token scan, node_modules for the Vectorize shape pins -- and so
 *  the only ones that must run under Node. Named once and referenced by both
 *  projects, so a file cannot end up in both or in neither. */
const FILESYSTEM_TESTS = [
  "test/forbidden-tokens.test.ts",
  "test/vectorize-shape.test.ts",
];

const IGNORED = ["**/node_modules/**", "**/dist/**", "**/.wrangler/**"];

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "static",
          environment: "node",
          include: FILESYSTEM_TESTS,
          exclude: IGNORED,
        },
      },
      {
        plugins: [
          cloudflareTest({
            // The pool reads the real Worker config, so tests see the same
            // compatibility flags, bindings, and entry point that deploys do.
            wrangler: { configPath: "wrangler.jsonc" },
            miniflare: {
              // Fake secrets for tests. Real Secrets live only in Cloudflare and
              // are never present locally, and D-09 forbids any automated login
              // to the real Apple ID — no CI, pre-commit, or post-deploy job
              // ever authenticates against it.
              //
              // THREE BINDINGS LEFT THIS BLOCK IN PHASE 13: the two that carried
              // the account credentials, and the login gate's shared secret. The
              // platform stops supplying all three, and a test that could still
              // read one would prove nothing about what shipped — it would assert
              // against a value only the test runner has. The suite's two fake
              // credentials are constants in `test/fixtures/bound-secrets.ts`
              // instead, which is the single source for them.
              //
              // The same argument the removed allow-list Secret settles one
              // directory over: a binding declared in two places with nothing
              // keeping them in step is a binding that drifts, and this file is
              // the half nothing fails on.
              bindings: {
                R2_ACCOUNT_ID: "test-account-id-not-real",
                R2_ACCESS_KEY_ID: "test-access-key-not-real",
                R2_SECRET_ACCESS_KEY: "test-secret-key-not-real",
                CONFIRM_SECRET: "test-confirm-secret-not-real",

                // The SEED half of the allow list, as the JSON array string the
                // real `vars` entry holds. The single write-only Secret this
                // replaces is gone from every file in this repository.
                //
                // Two addresses, because two different suites need one. The
                // first is what the authorize tests sign in as. The second is
                // user A from test/fixtures/two-users.ts, so the door test can
                // prove a listed grant is SERVED — without it that positive
                // control could not exist and every refusal beside it would be
                // vacuous. Both sit under the reserved `.invalid` domain, which
                // can never resolve, following the habit the fakes above set.
                //
                // WITHOUT THIS BINDING EVERY /authorize TEST GETS THE 503: an
                // absent seed parses as nobody, and the gate that answers 503
                // sits above the method dispatch, so neither verb reaches the
                // form.
                //
                // THE STORE HALF IS DELIBERATELY NOT HERE. `ALLOW_LIST_KV` is a
                // KV namespace, and namespaces reach this pool from
                // wrangler.jsonc rather than from `miniflare.bindings` — an
                // entry here would be a second declaration with nothing keeping
                // it in step with the first. A test that wants a value in the
                // store writes one through the pool's own binding.
                ALLOWED_APPLE_IDS_SEED:
                  '["listed-user@example.invalid","user-a@example.invalid"]',
              },
            },
          }),
        ],
        test: {
          name: "workers",
          include: ["test/**/*.test.ts"],
          exclude: [...IGNORED, ...FILESYSTEM_TESTS],
        },
      },
    ],
  },
});
