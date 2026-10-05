# First live acceptance: Mail only

The Free template uses Worker name `icloud-mcp` and `ACCESS_MODE: "mail-read-only"`. Missing or unknown modes on a Free runtime also restrict access. The deployment validator requires an explicit `mail-read-only`, `read-only` or `full` value.

All 47 schemas remain registered. Mail validation admits only 8 callbacks: `account_whoami`, `mail_imap_diagnose`, `mail_list_folders`, `mail_list_messages`, `mail_list_unread`, `mail_find`, `mail_get_message`, `mail_get_attachment`. The other 39, including DAV diagnostics, calendar, contacts and `changes_since`, are refused before their callback. Future names are refused by default. Upload routes return 403. Implicit indexing, backfill, AI and autonomous arming/rule execution are blocked. Existing revocation/expiry housekeeping remains.

**No application secret is required for this Mail-only phase.** The broader `read-only` mode allows 18 reads including `changes_since` and needs `CONFIRM_SECRET` for its markers. Full access also needs the save/autonomy keys. Those phases require separate authorization. Any secret transmission must use the approved user-protected entry path; do not generate and transmit secrets through assistant tools.

The current Apple path uses an app-specific password with 2FA; it does not implement Apple's compatible-app account authorization. The password is not read-only or Mail-only at Apple: this server enforces that restriction. Cloudflare stores it in encrypted OAuth grant properties, processes requested Mail data, and returns selected answers to the connected OpenAI client. No real mail goes to Workers AI in this phase. See [Apple's app-password instructions](https://support.apple.com/en-us/102654).

The final client is hosted ChatGPT/Work/Codex tooling, through the public Cloudflare HTTPS endpoint. Local configuration or a localhost client is not the deployment destination. See [OPENAI-CLOUD.md](OPENAI-CLOUD.md). Actual account availability and cloud connection must be verified; no connection has been made.

Start with IMAP diagnostics, at most ten headers, one chosen search/message and an optional chosen text/PDF attachment. No blanket mailbox scan. IMAP reads use EXAMINE and BODY.PEEK, so they do not mark messages seen. Evidence must omit contents, credentials and capability URLs.

Before full mode, separately approve real-data indexing, autonomous credentials, application secrets and intended categories of test writes. Switching back to restricted mode suspends rules but does not erase them or revoke grants. At the end, revoke the connection and its Apple app-specific password.

`npm run test:validation` uses synthetic accounts and remote bindings disabled. `npm run test:free` verifies full-mode routing and all original schemas. Neither deploys nor authenticates to Apple.
