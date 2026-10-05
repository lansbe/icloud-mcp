# Hosted OpenAI connection

Target: the existing `icloud-mcp` Worker, HTTPS `/mcp`, independent of the owner's computer. A local Codex `config.toml` entry is not the final connection. OpenAI documents remote plugin tools in hosted ChatGPT/Work; actual availability in the owner's account and the intended Codex cloud surface remains to be verified. [Hosted and local MCP distinctions](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

## Exact callback, not an origin wildcard

OpenAI requires copying the exact callback from the MCP connection management page. Its documented forms are `https://chatgpt.com/connector/oauth/{callback_id}` and, for eligible issuer-identifying servers or older connections, `https://chatgpt.com/connector_platform_oauth_redirect`. Do not invent a callback ID or assume the stable URI will be selected. [Official authentication requirements](https://developers.openai.com/plugins/build/auth).

Set the public configuration variable `OPENAI_REDIRECT_URI` to that exact observed URL. Until set, OpenAI callbacks fail closed. The server compares the entire raw URI during DCR and authorization, rejects extra queries, fragments, credentials, ports, alternate paths and host lookalikes, and retains the provider's registered-URI binding. It does not authorize all of `chatgpt.com`. Legacy Claude/loopback support is retained for parity.

The pinned OAuth provider advertises S256, DCR, token methods and issuer identification. Local tests verify metadata and an authorization response's exact `iss`; CIMD is disabled. This does not prove a live OpenAI connection or every client-specific error flow. If OpenAI reports another callback, verify its official support before adding it.

## User path after deployment approval

In the existing ChatGPT account, developer mode is under Settings → Security and login; account/workspace policy controls availability. In Plugins, add an MCP connection using the public `/mcp` URL, then inspect its management page for the callback. Configure it, refresh metadata, and authenticate using the user's protected browser flow. If the account lacks this capability, stop and report that fact; do not purchase an upgrade. This developer test does not require public directory publication. [Official connection/test guide](https://developers.openai.com/plugins/deploy/connect-chatgpt).

Only public callback metadata should be returned to the assistant. Never inspect OAuth codes, tokens, password fields, clipboard contents or secret-bearing network requests. No available tool in this task creates an arbitrary hosted MCP connection; the exposed Plugin Management tools cover existing plugin permissions/dependencies/removal. Use the supported account UI after authorization.

## Proof before calling it connected

Obtain the exact callback, complete actual hosted OAuth and a harmless `account_whoami`/IMAP diagnostic, then verify a designated Mail read in a hosted conversation independent of the local executor. Authentication errors, unsupported tool discovery or missing cloud availability remain blockers, not proof of connectivity. Mail reads, rules and scheduled cloud work have separate acceptance scopes; the first Mail-only session runs no rules or indexing.
