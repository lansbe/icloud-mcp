# Functional parity inventory

Upstream: [russellkmoore/icloud-mcp](https://github.com/russellkmoore/icloud-mcp), confirmed SHA **c40e748aa4c94ce8e8fff57adc70e5d761d9c91d**. Fork: [lansbe/icloud-mcp](https://github.com/lansbe/icloud-mcp), branch **free-workers**. MIT license and Russell Moore attribution retained. The code inventory finds **47 registered tools**, not an assumed count.

No tool registration, description or input schema is changed. The Free end-to-end test snapshots all 47 schemas at [application.test.ts.snap](../../test/free/__snapshots__/application.test.ts.snap); the README table remains generated from the registration inventory. Tool implementation files are unchanged. Existing unit/integration tests exercise the protocol logic; the Free tests exercise replaced platform adapters and authenticated routing using synthetic accounts. This does not mean 47 real iCloud calls were performed.

| Tool | Function | Free disposition |
| --- | --- | --- |
| `mail_imap_diagnose` | Diagnostics: Check iCloud IMAP connectivity, auth, and capabilities. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `dav_diagnose` | Diagnostics: Check CalDAV/CardDAV discovery: resolved URLs, shard host, cache hit, timings. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `account_whoami` | Diagnostics: Show which Apple ID this connection is signed in as — the full address, from this connection's own grant. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_list_folders` | Mail: List mail folders with role and counts. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_list_messages` | Mail: List a folder's messages, newest first (metadata + capped snippet, never bodies). | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_list_unread` | Mail: List a folder's unread mail. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_find` | Mail: Search one folder by keyword, sender, and date range. Exhaustive in that folder: an empty answer means no such mail is there. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_recall` | Mail: Find recent mail by meaning. Ranked and best-effort: an empty answer means nothing scored high enough, not that no such mail exists. Returns message ids and subjects only; open one with `mail_get_message`. It searches a copy of your recent mail this server keeps for everyone who signs in; [SECURITY.md](SECURITY.md#recall-keeps-a-searchable-copy-of-your-recent-mail) says what is kept and for how long. | Same embedding model and contracts; SQLite exact cosine; bounded global capacity. |
| `mail_recall_backfill` | Mail: Fill your own recall index in one sitting, while you watch. Each call indexes up to 10 pages of 25 messages of recent inbox and archive mail, one page at a time. A 20-second time limit usually stops it after 4 or 5 pages, about 100 to 125 messages. It says how far it has got. Call again until it says the index is built. It takes no arguments and only ever fills your own index. | Same embedding model and contracts; SQLite exact cosine; bounded global capacity. |
| `mail_get_message` | Mail: Read one message in full by opaque id. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_mark_read` | Mail: Mark one message read or unread. **Writes immediately** — no preview, because the same tool puts it back. Reports the state iCloud returned. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_flag` | Mail: Flag or unflag one message. **Writes immediately** — no preview, because the same tool puts it back. Reports the flag state iCloud returned. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_move` | Mail: Preview moving up to 25 messages from one folder to a folder you name, by folder id. Writes nothing; apply with `mail_commit`. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_archive` | Mail: Preview moving up to 25 messages to the account's own archive folder. Refuses if the account has none, rather than guessing. Writes nothing; apply with `mail_commit`. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_trash` | Mail: Preview moving up to 25 messages to Trash, where they can be moved back. Writes nothing; apply with `mail_commit`. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_delete_draft` | Mail: Preview moving one draft to Trash. Acts only on a draft in the drafts folder, exactly as the preview showed it. Writes nothing; apply with `mail_commit`. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_commit` | Mail: Apply a move, archive, Trash or draft-delete preview, only if the messages are unchanged since. Reports each message as `moved`, `copied_not_removed`, `not_copied` or `unknown`. Never removes mail for good. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_get_attachment` | Mail: Read one attachment as text: plain text, HTML, or PDF (its text is extracted). Other types are refused. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_compose_new` | Mail: Compose a new message **into Drafts** (never sent). | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_compose_reply` | Mail: Reply to a message **into Drafts**, threaded (never sent). | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `mail_stage_attachment` | Mail: Stage a file to attach to a draft (from a message, raw bytes, or an upload URL). | Same staging/save contracts; bounded SQLite blobs and same-origin signed upload. |
| `mail_save_attachment` | Mail: Save attachments to your own computer. One download link per file, valid five minutes. The local Claude session that has your folder connected (such as Claude Cowork) downloads it. | Same staging/save contracts; bounded SQLite blobs and same-origin signed upload. |
| `mail_confirm_upload` | Mail: Finish a presigned attachment upload. | Same staging/save contracts; bounded SQLite blobs and same-origin signed upload. |
| `calendar_list_calendars` | Calendar: List calendars: id, name, colour, subscription flag. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_create_calendar` | Calendar: Create a calendar with a name and a `#RRGGBB` colour. **Writes immediately** — no preview, because it is reversible. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_update_calendar` | Calendar: Rename a calendar, recolour it, or both. **Writes immediately** — no preview, because it is reversible. Reports which of the two actually changed. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_list_events` | Calendar: List events in a date range (recurring events expand to occurrences). | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_get_event` | Calendar: Read one event in full by opaque id. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_search` | Calendar: Find events by keyword or attendee within a range. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_find_free_slots` | Calendar: Find free slots across all calendars for a duration and range. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_create_event` | Calendar: Create an event. **With attendees, previews first** and returns a confirmation. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_update_event` | Calendar: **Preview** a change; writes nothing until `calendar_commit`. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_respond_to_invitation` | Calendar: **Preview** answering one invitation (accepted, declined or tentative) and who is told. A repeating invitation is answered for the whole series or refused. Writes nothing until `calendar_commit`. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_delete_event` | Calendar: **Preview** deleting one event; writes nothing until `calendar_commit`. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_delete_calendar` | Calendar: **Preview** deleting one calendar and every item in it; writes nothing until `calendar_commit`. The default calendar is not exempt. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `calendar_commit` | Calendar: Apply a previewed create/update/delete or invitation answer, using its confirmation token. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `contacts_search` | Contacts: Find contacts by name or email (rows carry addresses). | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `contacts_get` | Contacts: Read one contact in full by opaque id. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `contacts_create` | Contacts: **Preview** a new contact. Writes nothing until `contacts_commit`. Lists cards that already hold a value you supplied; nothing is merged. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `contacts_update` | Contacts: **Preview** one change to an existing contact. Send only the fields that change; the rest are kept. Writes nothing until `contacts_commit`. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `contacts_commit` | Contacts: Apply a previewed contact create or update, using its confirmation token. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `changes_since` | Changes: Say what changed since a marker from an earlier call: counts first, then new mail by sender, subject and whether it came from a mailing list (never a body), then each calendar's count of events added or changed and removed. Watches the inbox, or up to five folders you name. Returns a fresh marker every time. Never marks mail read. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `rules_list` | Rules: List your rules, whether the rules job is running for you, and what it did recently. Reads no mail. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `rules_add` | Rules: **Preview** adding a rule. Writes nothing; the preview's sentence names every condition and the action. Apply with `rules_commit`. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `rules_commit` | Rules: Add the rule `rules_add` previewed, using its confirmation token. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `rules_remove` | Rules: Remove one of your rules at once. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |
| `rules_test` | Rules: Try a rule on your newest 25 inbox messages and say what it would do. Writes nothing. | Original implementation and schema retained; executed behind Free OAuth/DO routing. |

## Cross-cutting parity

| Requirement | Evidence and limits |
| --- | --- |
| Exhaustive IMAP search, UIDs, paging, MIME and HTML | Original transport/parser/search/service and tests retained; no keyword approximation of IMAP search. |
| PDF extraction | Original unpdf parser and 2 MiB source ceiling retained; no OCR invented; image-only PDFs report no text layer. Local cold/warm profiler provided. |
| Download and staging | 20 MiB save, 4 MiB stage, 256 KiB inline, three attachments per draft retained; tests cover multi-chunk maximum sizes, TTL, partial uploads, wrong owner and replay. |
| DAV calendar and contacts | Original discovery, ETags, preview/commit, invite/recurrence/freebusy/addressbook behavior retained. |
| OAuth multiuser | Real local provider, encrypted grants and PKCE exchange; concurrent identities remain separate, credentials absent from replies. No real iCloud authentication. |
| Semantic retrieval | Full bge-m3 1024d, exact cosine, original score cutoff and owner double check; 10,000 entries/person, 40,000/deployment, 90-day active retention. |
| Autonomous rules | Original per-user alarms/leases/session queue/rule execution retained; only flag and draft reply actions; budgets can pause operation, see architecture capacity. |
| Preview and one-time commit | Original binding of preview to owner/host/content retained; spent claims moved from eventual KV to transactional SQLite. Eight simultaneous claims have exactly one winner. |
| No mail transmission | SMTP prohibition, socket choke point, write ownership and existing scanner/tests retained. Drafts never send. |
| Revocation/operations | Existing owner CLI supports ICLOUD_PROFILE=free for all remote commands; separate daily revocation reserve preserves cleanup after admission exhaustion. |

## Explicit differences

Free operation has bounded shared volume, four simultaneous application handlers, request body/time ceilings, exact rather than approximate vector ranking, same-origin uploads, active blob TTL 24h, and SQLite recovery retention. These are documented in [ARCHITECTURE.md](ARCHITECTURE.md). No promise of unlimited usage, isolated physical databases, cryptographic erasure, continuous multiuser rule scheduling or production Free eligibility is made. Cloud acceptance remains pending per [DEPLOY.md](DEPLOY.md).
