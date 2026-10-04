import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [cloudflareTest({
    wrangler: { configPath: "wrangler.free.jsonc" },
    remoteBindings: false,
    miniflare: { bindings: {
      CONFIRM_SECRET: "test-confirm-secret-not-real",
      SAVE_LINK_SEAL_KEY: "dGVzdC1zYXZlLWxpbmsta2V5LTMyLWJ5dGVzLWZha2U",
      AUTONOMY_SEAL_KEY: "dGVzdC1zZWFsLWtleS0zMi1ieXRlcy1ub3QtcmVhbCE",
      AUTONOMY_CLIENT_SECRET: "test-autonomy-client-secret-not-real",
      ALLOWED_APPLE_IDS_SEED: '["user-a@example.invalid","user-b@example.invalid"]',
    } },
  })],
  test: { include: ["test/free/**/*.test.ts"], testTimeout: 60000 },
});
