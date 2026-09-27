// The single source of truth for this project's forbidden-token ban (FND-06,
// D-11, D-12, D-13).
//
// `test/forbidden-tokens.test.ts` imports this module and `.husky/pre-commit`
// invokes it, so the test-time gate and the commit-time gate can never disagree
// about what is banned. The prose statement of the same ban, with its full
// rationale, lives in the Conventions section of ./.claude/CLAUDE.md (D-14) --
// that is the preventive layer, this is the detective one.
//
// Plain Node ESM, `node:fs` and `node:path` only. No dependencies, because the
// pre-commit hook runs before anything guarantees `node_modules` is installed.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

/** Repository root, derived from this file's own location rather than from
 *  `process.cwd()`. The hook runs from wherever git invoked it and vitest runs
 *  from the project root; neither should change what gets scanned. */
export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The ban list.
 *
 * Every entry carries a non-empty `why`. That string is not decoration -- it is
 * what the hook prints when it rejects a commit, and a rule without a reason is
 * a rule a future session will reason its way around.
 *
 * `scope`, when present, restricts a rule to files whose repo-relative path
 * starts with that prefix. It is a directory prefix rather than a list of file
 * names on purpose: a rule scoped to a directory holds for the files later
 * phases add to it, and does not depend on any particular file existing yet.
 */
export const FORBIDDEN = [
  // ---------------------------------------------------------------- transport
  // Criterion 4 / FND-06. See ./.claude/CLAUDE.md for the full rationale.
  {
    id: "tls-upgrade-call",
    pattern: /\bstartTls\b/g,
    why: "The opportunistic-TLS upgrade call is broken in this runtime's socket API (workerd#2712, still open, no confirmed fix). Implicit TLS on 993 covers every need this project has.",
  },
  {
    id: "tls-upgrade-mode",
    pattern: /["']starttls["']/gi,
    why: "The opportunistic-TLS transport mode is banned. connectImap() passes an implicit-TLS literal and takes no transport argument.",
  },
  {
    id: "cleartext-imap-port",
    pattern: /\bport\s*[:=]\s*143\b/gi,
    why: "Port 143 is cleartext IMAP and would require the banned TLS upgrade. IMAPS on 993 is the only permitted port.",
  },

  // -------------------------------------------------------------------- send
  // D-12. Broader than criterion 4's literal wording, deliberately: no-SMTP-send
  // is the project's load-bearing safety boundary, not a scoping accident.
  {
    id: "smtp-submission-port",
    pattern: /\bport\s*[:=]\s*(?:25|465|587)\b/gi,
    why: "SMTP submission ports are banned. Claude drafts; the human reviews and sends. That human step is the project's actual backstop against prompt-injected email content reaching an outbound message -- removing it is a safety regression, not a feature.",
  },
  {
    id: "host-with-banned-port",
    // A hostname-shaped prefix (something containing a dot and a letters-only
    // suffix) followed by a banned port. Requiring the hostname shape is what
    // keeps this off `"12:25"` and every other colon-number string.
    pattern: /["'][^"'\s]*\.[a-z]{2,}:(?:25|143|465|587)\b/gi,
    why: "A host:port literal naming a cleartext-IMAP or SMTP-submission port. Only imap.mail.me.com over IMAPS is reachable from this codebase.",
  },
  {
    id: "mail-sending-library",
    pattern:
      /(?:\bfrom|\brequire\(|\bimport\()\s*["'](?:nodemailer|worker-mailer|emailjs|emailjs-smtp-client|@sendgrid\/mail|mailgun\.js|postmark|resend)["']/gi,
    why: "A mail-sending library import. This project must not acquire the ability to send mail; see the SMTP submission port entry for why that boundary is load-bearing.",
  },

  // ------------------------------------------------------------------ removal
  // Phase 21, TRIA-07, D-10. iCloud has no move command, so a move here is the
  // copy, proven from the server's reply, then the removal of that ONE UID.
  // These two rules ban the two ways to get that wrong on the wire.
  //
  // WHAT EACH CATCHES. `mailbox-wide-expunge` catches a command line that starts
  // with the bare removal command or with CLOSE, either after an interpolated
  // tag (`${tag} ...`) or at the head of a string handed to the generic sender.
  // RFC 3501 gives both the same reach: every message in the folder that
  // carries the removal flag, including ones Apple Mail flagged and the user
  // can still recover (PITFALLS #31; CLOSE per RFC 3501 §6.4.2). Its second
  // half catches the UID-scoped removal when it names a range or a star, which
  // reaches every flagged message in that range just as the bare form does.
  // `move-command` catches the RFC 6851 move command, with or without its UID
  // prefix, at the same two anchors.
  //
  // WHAT NEITHER SEES. A lowercase command word. A command word held in a
  // variable and handed to the sender. A range built somewhere the pattern
  // cannot see and interpolated as one value. Those are held one layer up, by
  // the byte-exact recorded lines in test/move.test.ts, which read what was
  // actually written rather than the shape of the code that wrote it.
  //
  // THE PROSE DISCIPLINE. Both patterns read comments, and both are scoped to
  // the whole of `src/`. So describe both commands BY ROLE anywhere under
  // `src/` -- "the removal of that one UID", "the move command" -- and never
  // quote them. A comment that quotes one fails the check it was explaining,
  // and the failure arrives as a pre-commit rejection in an unrelated plan.
  // Tests and fixtures spell these on purpose, which is why the scope is `src/`.
  {
    id: "mailbox-wide-expunge",
    scope: "src/",
    pattern:
      /(?:\$\{[^}\n]*\}\s*|["'`]\s*)(?:EXPUNGE|CLOSE)\b|\bUID EXPUNGE\s+[^"'`\n]*[:*]/g,
    why: "A removal that can reach a message this call did not copy. RFC 3501's bare removal command and CLOSE both remove EVERY message flagged for removal in the folder, including ones Apple Mail flagged and the user can still recover (PITFALLS #31), and a UID-scoped removal naming a range or a star reaches every flagged message in that range the same way. The only removal this project permits is the UID-scoped one naming the single UID whose copy COPYUID just proved (TRIA-07), and the teardown sends LOGOUT only. The answer is the move step in src/mail/triage.ts, never a narrower pattern.",
  },
  {
    id: "move-command",
    scope: "src/",
    pattern: /(?:\$\{[^}\n]*\}\s*|["'`]\s*)(?:UID\s+)?MOVE\s/g,
    why: "The RFC 6851 move command. iCloud does not advertise it, and RFC 6851 §3 forbids a client from issuing it unless the server advertises it, so \"try it and fall back\" is a protocol violation that works until the day it does not. Every move in this project is the copy, proven from COPYUID, then the conditional removal mark, then the removal of that one UID -- in src/mail/triage.ts. Use that step; do not narrow this pattern.",
  },

  // ------------------------------------------------------- credentials in logs
  // FND-03, Pitfall 6. IMAP's LOGIN command carries the password inline in the
  // command stream, so there is no separately-named field a redactor could
  // target. The only reliable defence is that the credential path does not log.
  // Phase 8, CRED-05 (D-08). The last two names are not bindings. They are the
  // field names the grant's props use for the same two values, and they sit
  // beside the binding names because the leak is the same leak: a per-user
  // credential reaches a retained log through a line that names it. The three
  // binding names stay on the list even after the bindings themselves are
  // retired, because a rule that only refuses more costs nothing to keep.
  //
  // What it does not see: a different spelling or letter case of a name. The
  // names match as whole identifiers, with a word boundary on each side and no
  // case-insensitive flag, so a longer identifier that merely starts with one
  // is not caught. The rule below it for the props object is the wider net.
  //
  // Phase 9 (D-02). THE METHOD PART MATCHES ANY IDENTIFIER, IN ANY LETTER CASE.
  // It used to be lower-case letters only, so a timed-log or collapsed-group
  // call that passed a secret fired nothing here. The method is now any
  // identifier, with white space allowed before the parenthesis. Only the
  // method part changed: the span and the name list are what they were.
  //
  // WHAT THE METHOD PART STILL DOES NOT SEE. A computed member on the console
  // object, where the method name is a string in square brackets. A method
  // pulled out by destructuring and then called bare. An alias of the console
  // object, called through its new name. The optional-call form, where a
  // question mark and a dot sit between the method and the parenthesis. A
  // logger that is not named by either of the two words the pattern opens
  // with. All five are evasions rather than accidents, and this rule is aimed
  // at the accident. They are pinned by a test row that asserts the rule does
  // NOT fire on them, so nobody believes they are covered.
  //
  // THE MEMBER ACCESS WAS WIDENED TOO, IN ALL FIVE RULES TOGETHER (code review
  // WR-02). They used to demand a bare dot with nothing around it, and two
  // shapes therefore fired nothing. The first is an ACCIDENT, and it is why
  // this changed: the formatter breaks a long call after the object name, so a
  // debug line carrying a wide object is exactly the line that wraps. The
  // second is the optional-chaining member access, a question mark BEFORE the
  // dot. That is not the optional-CALL form listed above, which has the
  // question mark AFTER the method name and still escapes. White space, a new
  // line and an optional question mark are now allowed on either side of the
  // dot, in every rule that opens with these two words, so the five cannot
  // disagree with each other about it. The two new shapes only refuse more,
  // and each rule carries its own sample of both in the test file.
  {
    id: "secret-binding-in-log-call",
    pattern:
      /\b(?:console|logger)\s*\??\.\s*[A-Za-z_$][\w$]*\s*\([^)]*\b(?:APPLE_APP_PASSWORD|APPLE_ID|AUTH_SECRET|appPassword|appleId)\b/g,
    why: "A logging call whose arguments mention a secret binding name, or one of the two credential field names the grant's props carry. A log line naming either field leaks the Apple ID or the app-specific password. Credentials must never reach a log, an error, or a tool response. THREE OF THE FIVE NAMES ARE DEAD BINDINGS and they stay on purpose: phase 13 deleted the account bindings and the login gate's secret from the platform, so nothing supplies those three now, but the rule only refuses MORE by keeping them -- and what it catches is a future session re-introducing a binding under one of those exact names, which is the singular-owner assumption coming back. Do not tidy them out. The two live names are the grant-props fields, and they are why this rule still has work to do.",
  },
  // Phase 9 (D-02). Widened together with the blanket src/ rule below, so the
  // two cannot drift: both listed the same six method names, and both now
  // match any method. D-02 does not name this rule. It had the same gap, the
  // same fix closes it, and it only refuses more.
  {
    id: "logging-on-the-credential-path",
    scope: "src/mail/",
    pattern: /\b(?:console|logger)\s*\??\.\s*[A-Za-z_$][\w$]*\s*\(/g,
    why: "No logging call of any kind may exist under src/mail/. The LOGIN command line is itself the credential, so a 'log what I am about to write' line leaks it with no secret-named variable anywhere in sight.",
  },
  // The two rules above do not compose to cover Convention 4's stated rule, and
  // the gap between them is directory-shaped. The one above is scoped to
  // src/mail/, so anything outside it may log freely. The one above that needs a
  // binding NAME inside the argument list. A call in src/mcp/ or src/auth/ that
  // passes the whole environment object matches neither -- and that object holds
  // every secret this Worker has. These two close it, and the second is
  // deliberately unscoped so it reaches scripts/ and test/ as well.
  //
  // Phase 9 (D-02). THE METHOD PART MATCHES ANY IDENTIFIER, IN ANY LETTER CASE.
  // It used to list six method names. "No logging call of any kind" was the
  // rule's own claim, and the list did not hold it: a table or dir call was
  // free to log under src/, and so was a timed-log or collapsed-group call
  // that passed the grant's props, which fired nothing anywhere. The method is
  // now any identifier. This landed before the first code under src/ held a
  // principal, on purpose.
  //
  // WHAT IT STILL DOES NOT SEE. A computed member on the console object, where
  // the method name is a string in square brackets. A method pulled out by
  // destructuring and then called bare. An alias of the console object, called
  // through its new name. The optional-call form, where a question mark and a
  // dot sit between the method and the parenthesis. A logger that is not named
  // by either of the two words the pattern opens with. All five are evasions
  // rather than accidents. Naming them here is what stops a later reader
  // believing "no logging under src/" is proven by this rule alone. They are
  // pinned by a test row that asserts the rule does NOT fire on them.
  //
  // THE MEMBER ACCESS WAS WIDENED TOO (code review WR-02). See the paragraph
  // above the first rule in this section: white space, a new line and an
  // optional question mark are allowed on either side of the dot, in all five
  // rules together. The line-broken form is the accident the formatter
  // produces, and it is why this rule's own claim — no logging call of any
  // kind under src/ — was not what the rule enforced.
  {
    id: "logging-anywhere-under-src",
    scope: "src/",
    pattern: /\b(?:console|logger)\s*\??\.\s*[A-Za-z_$][\w$]*\s*\(/g,
    why: "No logging call of any kind may exist under src/, not only under src/mail/. The environment binding carries the confirmation-signing secret and the attachment bucket's credentials, and the signed-in person's Apple ID and app-specific password ride in the grant's props one argument away from any of it, so one debug line that passes the environment or the props names no secret and leaks whatever it was handed -- and observability logging is enabled, so 'a log' means retained Cloudflare storage, not a terminal. The rule was written when the environment carried the account credentials directly; it is blunt for the same reason now that they arrive per person instead.",
  },
  {
    // No `scope`, on purpose: this one holds in every scanned directory. A
    // throwaway script or a test helper that prints the environment leaks the
    // same three values as a Worker that does.
    //
    // Phase 9 (D-24). THE METHOD PART MATCHES ANY IDENTIFIER, IN ANY LETTER
    // CASE. It used to be lower-case letters only, the same gap the two name
    // rules beside it had, so a timed-log or collapsed-group call that passed
    // the environment object fired nothing outside src/. Only the method part
    // changed: the span is what it was.
    //
    // WHAT THE METHOD PART STILL DOES NOT SEE. A computed member on the console
    // object. A method pulled out by destructuring. An alias of the console
    // object. The optional-call form. A logger that is not named by either of
    // the two words the pattern opens with. The comment above the first rule
    // in this section spells each one out, and a test row pins all five.
    //
    // THE MEMBER ACCESS WAS WIDENED TOO (code review WR-02), with the other
    // four: white space, a new line and an optional question mark on either
    // side of the dot. A wrapped call passing the environment object is the
    // exact line this rule exists for, and it used to commit cleanly.
    id: "env-object-in-log-call",
    pattern: /\b(?:console|logger)\s*\??\.\s*[A-Za-z_$][\w$]*\s*\([^)]*\benv\b/g,
    why: "A logging call whose arguments mention the bare environment object. It carries the confirmation-signing secret and the attachment bucket's credentials, so nothing needs to name a secret for something that must not be retained to reach the log -- which is exactly the shape the secret-binding rule cannot see. It carried the account credentials directly until phase 13 moved those into the grant's props; the rule is unchanged, because a bare environment object is still a bag of secrets whose contents nobody reads at the call site.",
  },
  // Phase 8, CRED-05 (D-07). The rule above, moved to where the credentials
  // live next. Once each user signs in with their own account, the Apple ID and
  // the app-specific password travel in the grant's props, and the principal
  // built from them is the handle on the password. A log line that passes any
  // of those names no secret, so the two rules above cannot see it.
  //
  // THE SPAN IS BOUNDED BY THE STATEMENT, and the two older logging rules above
  // keep the paren-bounded span. The difference is deliberate. A span that
  // stops at the first closing parenthesis ends at an INNER call's parenthesis,
  // so a log call whose first argument is itself a call hides the props behind
  // it. The concurrency rules below made the same choice for the same reason.
  // The older rules are left exactly as they are: changing a shipped span is a
  // change to a shipped rule, and this phase adds rules without touching one.
  //
  // FIVE NAMES, where D-07 lists four. The fifth is the one password reader. A
  // log call that passes what it returns is the most direct leak there is, and
  // a principal held in a variable with another name would hide it from the
  // other four. It only refuses more. To drop it, delete that one name here and
  // in PROPS_LOG_NAMES in test/forbidden-tokens.test.ts.
  //
  // WHAT IT DOES NOT AND CANNOT SEE. A variable with another name. A field
  // pulled out first and logged under a new name. A logger that is not called
  // by either of the two names the pattern opens with. A direct write to an
  // output stream. An argument list that runs past 400 characters, or one with
  // a semicolon before the name. A different spelling or letter case of a
  // listed name: the names match as whole identifiers, with a word boundary on
  // each side and no case-insensitive flag. All of these are evasions rather
  // than accidents, and this rule is aimed at the accident. Under src/ the
  // blanket logging rule above still refuses every one of them that is a
  // logging call. Naming the gaps here is what stops a later reader believing
  // the rule proves more than it does.
  //
  // WHAT IT SEES BY MISTAKE, AND WHY THAT STAYS (code review WR-02). The rule
  // reads text, not syntax, so a listed name counts wherever it sits in the
  // span: inside a string literal, inside a comment, or in the NEXT statement
  // when the logging call has no semicolon after it. One of the five names is
  // also everyday DAV vocabulary. The discovery code under src/dav/ is built
  // around the current-user resource that the DAV specs call by that same
  // word, so a script or a test helper that logs a plain message about DAV
  // discovery is refused, and nothing in it touches a credential.
  //
  // That is a recorded choice and not a bug to fix. A pattern that skipped
  // strings would also skip a template literal that interpolates the real
  // object, which is a leak. WHEN THIS FIRES ON AN INNOCENT LINE: reword the
  // message so it does not hold a listed name as a whole word, or end the
  // logging call with a semicolon. Never loosen the name list or the span.
  // Under src/ the question does not come up, because every logging call there
  // is refused anyway. The over-match is pinned by test rows that assert the
  // rule DOES fire on those lines, so a later "fix" that narrows it goes red.
  //
  // Phase 9 (D-02). THE METHOD PART MATCHES ANY IDENTIFIER, IN ANY LETTER CASE.
  // It used to be lower-case letters only, so a timed-log or collapsed-group
  // call that passed the props fired nothing here, and nothing anywhere else
  // either. That was the gap closed before the first caller of the principal
  // landed. Only the method part changed: the statement-bounded span and the
  // five names are what they were.
  //
  // WHAT THE METHOD PART STILL DOES NOT SEE, added to the list above. A
  // computed member on the console object, where the method name is a string
  // in square brackets. A method pulled out by destructuring and then called
  // bare. An alias of the console object, called through its new name. The
  // optional-call form, where a question mark and a dot sit between the method
  // and the parenthesis. A logger that is not named by either of the two
  // words the pattern opens with. All five are pinned by a test row that
  // asserts the rule does NOT fire on them.
  //
  // THE MEMBER ACCESS WAS WIDENED TOO (code review WR-02), with the other
  // four: white space, a new line and an optional question mark on either side
  // of the dot. A call passing the grant's props is long by nature, so the
  // formatter's line break after the object name is the likeliest shape this
  // rule will ever meet.
  {
    // No `scope`, on purpose: this one holds in every scanned directory. A
    // throwaway script or a test helper that prints the grant's props leaks the
    // same two values as a Worker that does.
    id: "props-object-in-log-call",
    pattern:
      /\b(?:console|logger)\s*\??\.\s*[A-Za-z_$][\w$]*\s*\([^;]{0,400}?\b(?:props|principal|authInfo|getMcpAuthContext|passwordOf)\b/g,
    why: "A logging call whose arguments mention the grant's props, the principal, the auth info, the auth context reader or the password reader. The grant's props carry the Apple ID and the app-specific password, so a log line that passes them names no secret and leaks both -- and observability logging is enabled, so 'a log' means retained Cloudflare storage, not a terminal. The rule reads text, so it also fires when one of those names is only a word inside the message string or a comment, or sits in the next statement after a logging call with no semicolon. If that is what happened, reword the message or add the semicolon. Do not loosen this rule.",
  },

  // ---------------------------------------------------- writes onto the env object
  // Phase 8, CRED-05 (D-09). The environment object is shared: by every test in
  // a file, and by every request an isolate serves. A write onto it changes who
  // the NEXT caller runs as, and nothing at the write site says so. It matches
  // nothing on the real tree today, and it is here before the per-user code is
  // written so that code is bound by it from its first commit.
  //
  // Three forms, the ones D-09 names: a member assignment, an index assignment,
  // and the object-merge call with the environment object as its TARGET. An
  // accessor chain is required before the operator, so declaring or rebinding a
  // local with this name is not a hit. The operator may be plain or compound,
  // and must not be the start of a comparison or an arrow. A spread copy with
  // fields overridden is a new object and is left alone: that is the permitted
  // form, and it is what the two-user test fixture does.
  //
  // WIDENED AFTER CODE REVIEW (WR-01). The first version needed the accessor
  // chain to start right after the object's name, and the type checker pushes
  // people away from that spelling. A plain write is a type error, so the next
  // thing an author tries is a type cast in parentheses, or a non-null mark.
  // Both sat between the name and the chain and hid the write. That is an
  // accident, not an evasion, and it is the exact case this rule exists for.
  // The rule now also sees:
  //   - a type cast in parentheses before the chain, single or chained;
  //   - a non-null mark after the name, or between two links of the chain;
  //   - the postfix increment and decrement;
  //   - the prefix increment and decrement, which is its own arm because the
  //     operator comes BEFORE the name. That arm needs an accessor right after
  //     the name with no space, so a command-line flag spelled with two dashes
  //     and this name is not a hit when a space, an equals sign or the end of
  //     the string follows the name. A flag with a DOTTED suffix is a hit: see
  //     the over-match section below;
  //   - a computed key that itself holds one level of square brackets.
  // Every one of these refuses more and none refuses less. Each has its own
  // sample row in ENV_WRITE_FORMS in test/forbidden-tokens.test.ts.
  //
  // THE NON-NULL MARK OWNS THE WHITE SPACE IN FRONT OF IT, AND ONLY THAT (second
  // code review, WR-01). Inside the chain loop the mark and its leading white
  // space are optional TOGETHER, as one group, and one white-space run follows.
  // The first widened version had a white-space run on EACH side of an optional
  // mark. With no mark present, one space before a dot could be taken by either
  // run, which is two ways to match every link. On a chain that does not end in
  // a write the engine tried every combination, so the cost doubled per link:
  // about 25 spaced links took seconds, and a new line counts as white space,
  // so an ordinary multi-line chain has that shape. This rule has no scope and
  // runs in both gates, so one such line would hang the hook with no message.
  // The two forms match exactly the same strings. Do not split that group back
  // into two optional pieces. A timing test in test/forbidden-tokens.test.ts
  // holds it, over several thousand spaced links and a multi-line variant.
  //
  // EVERY ARM OF THE COMPOUND-OPERATOR GROUP HAS ITS OWN SAMPLE ROW TOO (code
  // review WR-04), in ENV_COMPOUND_OPERATORS in the same test file. An arm with
  // no sample can be deleted with the whole suite still green, because the
  // set-equality guard works at the rule level and cannot see inside a group.
  // Adding an operator here means adding its row there.
  //
  // WHAT IT DOES NOT AND CANNOT SEE. The delete form. The property-definition
  // call and the reflective set call. An alias of the object, written through
  // under another name. A destructuring assignment. A bare rebinding of a local
  // with this name, which changes no shared object and is not a leak. A type
  // cast written with angle brackets before the name, or with the newer
  // type-check keyword in place of the cast keyword. A cast whose type holds a
  // closing parenthesis or runs past 80 characters. A computed key with square
  // brackets nested more than one level deep. A
  // different spelling or letter case of the object's name. All have zero hits
  // today. These are evasions rather than accidents, and this rule is aimed at
  // the accident. Naming the gaps here is what stops a later reader believing
  // the rule proves more than it does.
  //
  // WHAT IT SEES BY MISTAKE, AND WHY THAT STAYS (code review WR-03). The rule
  // is anchored on the WORD and not on the object, and it reads text, not
  // syntax. Three innocent shapes are refused:
  //   - a write onto the Node process's own environment table, which is a
  //     normal thing for a file under scripts/ to do;
  //   - a write onto the build tool's environment table, the one that hangs
  //     off the module metadata object;
  //   - a COMMENT or a string that spells the banned form out as an example.
  // The third is the trap CLAUDE.md sections 1 and 2 already warn about for
  // other rules: a comment that explains a ban by example fails the check it
  // explains, and the failure arrives as a rejected commit in the middle of
  // unrelated work. DESCRIBE THE BANNED FORM BY ROLE in comments and test
  // titles -- "a write onto the environment object" -- and never by example.
  // This comment does exactly that.
  //
  // TWO MORE, FROM THE PREFIX ARM (second code review, IN-05). That arm opens on
  // two dashes, allows a space, then wants the name and an accessor. So it also
  // fires on:
  //   - a double dash used as PUNCTUATION in a comment or a string, right in
  //     front of a plain read of a field on this object. Nothing in such a line
  //     spells a write out, so "describe it by role" does not help its author:
  //     the line already does. The plain fix is a different dash, or a word
  //     between the dash and the name;
  //   - a command-line flag spelled with two dashes, this name, a dot and a
  //     suffix. Pass the value as its own argument instead.
  // Both stay, for the same reason as the three above: a pattern cannot tell a
  // decrement from a dash, and a rule that skipped comments and strings would
  // skip real code held in a template.
  //
  // That is a recorded choice and not a bug to fix. Anchoring on the object
  // would need the rule to know which object a name refers to, and a pattern
  // cannot. A dotted-path exception would also hide a write through any holder
  // of the real object, which is a form the rule sees today on purpose. WHEN
  // THIS FIRES ON AN INNOCENT LINE: set the process variable from outside the
  // script (the command line or the runner's config), or hand a child process
  // a fresh copy with the field overridden, or reword the comment. Never
  // loosen the pattern. The over-match is pinned by test rows that assert the
  // rule DOES fire on those lines, so a later "fix" that narrows it goes red.
  {
    // No `scope`, on purpose: a test that writes an identity onto the shared
    // object is the realistic case, so the rule has to reach test/ and scripts/
    // as well as src/.
    id: "env-assignment",
    pattern:
      /\benv\b(?:\s+as\s+[^)\n]{1,80}\))?(?:(?:\s*!)?\s*(?:\.\s*[A-Za-z_$][\w$]*|\[[^\]\n]*\]|\[[^\[\]\n]*(?:\[[^\[\]\n]*\][^\[\]\n]*)+\]))+\s*(?:(?:\*\*|<<|>>>?|&&|\|\||\?\?|[-+*\/%&|^])?=(?![=>])|\+\+|--)|(?<![\w$)\]+\-])(?:\+\+|--)[ \t]*\(?[ \t]*(?:[\w$]+\.)*env\b(?:\s+as\s+[^)\n]{1,80}\))?!?(?:\.[A-Za-z_$]|\[)|\bObject\.assign\s*\(\s*(?:[\w$]+\.)*env\b/g,
    why: "A write onto the environment object: a member assignment, an index assignment, an increment or decrement, or an object merge with it as the target, with or without a type cast or a non-null mark in front of the accessor. That object is shared by every test in a file and every request in an isolate, so a write onto it is how one user's identity leaks into another test or another request. Build a fresh copy with the two account fields overridden instead. The rule matches the word and reads text, so it also fires on a write onto the Node process's environment table or the build tool's, and on a comment or string that spells the write out. If that is what happened, set the variable from outside the script or pass a fresh copy, or describe the form by role in the comment. It also fires on a double dash used as punctuation right before a read of a field on this object, and on a command-line flag made of two dashes, this name, a dot and a suffix. If that is what happened, use a different dash or put a word between, or pass the flag's value as its own argument. Do not loosen this rule.",
  },

  // -------------------------------------------------------------- concurrency
  // D-10. The detective half of the one-socket-per-request limit; the structural
  // half is connectImap()'s empty parameter list in src/mail/socket.ts.
  {
    id: "concurrent-connect",
    scope: "src/",
    // Bounded by the statement, not by the next closing parenthesis: the
    // realistic fan-out is `combinator(folders.map(() => ... connectImap()))`,
    // and the `()` of the arrow function would end a `[^)]*` span before the
    // connect call was ever reached. The teardown wait in
    // src/mail/imap-session.ts is a combinator too, and stays clean because it
    // names no connect helper anywhere in its statement.
    pattern: /\bPromise\.(?:all|allSettled|any|race)\s*\([^;]{0,400}?connectImap/g,
    why: "A concurrent combinator wrapped around the socket choke-point. Production allows six simultaneous connections per Worker invocation and that budget counts KV reads and outbound fetches too -- the OAuth provider spends one before any mail code runs. No wrangler key expresses this (the upstream request did not ship) and `wrangler deploy --dry-run` validates nothing inside a limits block, so this rule is the only thing that catches a fan-out. One live socket per request.",
  },
  // D-46. The same limit one layer up. The rule above guards the raw connect
  // call; this one guards the orchestrator every mail tool actually reaches
  // for, which is where a fan-out would realistically be written -- nobody
  // writes `Promise.all` around `connectImap()` directly, because nothing but
  // `withMailSession` calls it.
  //
  // Same statement-bounded span as the rule above, for the same reason: the
  // realistic fan-out is `combinator(refs.map((ref) => withMailSession(...)))`
  // and the arrow function's own `()` would end a `[^)]*` span before the
  // guarded call was ever reached.
  //
  // Phase 20 (D-07) added a second orchestrator, the mutating one, over the
  // same private core and the same request gate. So there are two prefixes
  // now, and both are named in the alternation. Each is still a prefix match:
  // the over-a-stream variants (`...Over`) are covered by the same name,
  // because a session over an already-open stream is still one conversation
  // against the account, and N of them is N. The private core's name begins
  // with the read prefix on purpose, so a fan-out written around the core is
  // covered too. A test reads every session-opening function name out of
  // src/mail/service.ts and runs a fan-out around each through this rule, so
  // a new orchestrator whose name escapes both prefixes goes red there.
  //
  // The triage verbs are NOT listed. A fan-out written around a verb at the
  // tool layer is refused at run time by the shared gate, which the verbs
  // reach through the mutating orchestrator. Listing names is also not free: a
  // name missing from an alternation is invisible to every set check, which
  // is the hole `DAV_WRITE_MODULES` exists to close for the DAV rule below.
  // Phase 21, which adds list operations over several messages, is where
  // listing the verbs gets revisited.
  {
    id: "concurrent-session",
    scope: "src/",
    pattern:
      /\bPromise\.(?:all|allSettled|any|race)\s*\([^;]{0,400}?(?:withMailSession|withMutatingMailbox)/g,
    why: "A concurrent combinator wrapped around either mail session orchestrator (read-only or mutating) or the core under them. Every session is a socket, so a fan-out over N mailboxes opens N of them: production allows six simultaneous connections per Worker invocation (counting KV reads and outbound fetches, one of which the OAuth provider has already spent), and iCloud's own per-account ceiling is lower, undocumented, and deliberately unmeasured because exhausting it locks the user out of their own mail in Mail.app on their own devices. The structural half is the request-scoped gate in src/mail/service.ts, which refuses a second acquire at runtime; this is the detective half, which refuses it at commit time. An account-wide sweep or search must be serial.",
  },
  // The same property one protocol over, and the reason is deliberately NOT the
  // same. The two rules above lean on the six-connection platform cap. That cap
  // does not bite here in the way it reads: workerd does not error on a seventh
  // simultaneous connection, it QUEUES it until one of the six receives its
  // response headers, so exhausting the platform budget degrades to latency.
  // Overstating it would be the kind of reason a future session correctly
  // disproves and then dismisses the whole rule over. The real exposure is
  // iCloud's own ceiling, and that one is stated accurately below.
  //
  // Same statement-bounded span as the two rules above, for the same reason the
  // comment at the top of this section gives: the realistic fan-out is
  // `combinator(calendars.map((c) => fetchCalendarObjects(...)))` and the arrow
  // function's own `()` would end a `[^)]*` span before the guarded call was
  // ever reached.
  //
  // The alternation names THREE layers, and the scope is `src/` rather than
  // `src/dav/` for the sake of the third.
  //
  // T-03-27 claimed this rule was "modelled directly on the two existing
  // combinator rules". It was not, and 03-REVIEW.md WR-03 found the gap: the
  // raw-name half below is modelled on `concurrent-connect`, which guards the
  // primitive, while the rule it was supposed to mirror is
  // `concurrent-session`, which guards the ORCHESTRATOR and is scoped to the
  // whole of `src/` in order to reach it. Scoped to `src/dav/` over tsdav names
  // only, `Promise.all(ids.map((id) => getEvent(env, davFetch, id)))` written in
  // `src/mcp/tools/calendar.ts` matched nothing at all -- and that is the layer
  // a fan-out actually gets written at, for exactly the reason the mail rule
  // gives: nobody wraps a combinator around a library primitive, because the
  // tool code never sees one.
  //
  // So, innermost outwards:
  //
  //   - `davFetch` -- what a hand-rolled request reaches for.
  //   - the tsdav standalone functions -- what a "just fetch them all" edit
  //     inside `src/dav/` reaches for.
  //   - the service entry points, plus `withRediscovery` and `pagedEvents` --
  //     what a tool reaches for, and the only names visible from `src/mcp/`.
  //     Every one of them ends in one or more DAV round trips, so N of them
  //     concurrently is N conversations against one account.
  //
  // Each of those three layers carries a WRITE half as well as a read half, and
  // the write half is the sharper argument. The account-wide read sweep this
  // rule's reason cites was withdrawn because it could not be repaired by
  // making it concurrent -- but a read that loses the race merely returns a
  // worse answer, and the user's calendar is unchanged either way. A sweep over
  // WRITES cannot be repaired at all: each request in it changes the user's
  // calendar, so a half-completed fan-out leaves a state nobody chose, no retry
  // can describe it, and the events it did reach cannot be put back. "Clear my
  // calendar for August" is one sentence, and a combinator over a map is the
  // first thing anyone reaching for it writes -- which is precisely why the
  // three write helpers and the four service write entry points are named here
  // rather than left to the structural half alone.
  //
  // `resolveOrganizerAddress` is named on the same footing as `withRediscovery`
  // and `resolveDavAccount`: it is not a write, but it costs one PROPFIND at
  // the principal and is reachable from `src/mcp/`. It was already covered by
  // accident -- its body wraps `withRediscovery`, which is on this list -- and
  // covering a name by accident is how a guarantee quietly leaves when the body
  // is refactored. Its sibling `planCreateTarget` is deliberately absent: that
  // one mints a UID and a URL synchronously and issues no request, and this
  // rule's subject is round trips against one account.
  //
  // The EIGHT composite entry points at the end of the alternation --
  // `applyCommit`, `buildPreview`, `buildDeletePreview`, `buildCreatePreview`,
  // `occurrenceBody`, `scopelessBody`, `applyNarrowedDelete` and
  // `observeDelivery`, all in
  // `src/mcp/tools/calendar.ts` -- are named for exactly the reason
  // `resolveOrganizerAddress` is, and it is the sentence in the paragraph above:
  // every one of them was covered BY ACCIDENT, because every one of their bodies
  // calls a name already on this list, and covering a name by accident is how a
  // guarantee quietly leaves when the body is refactored.
  //
  // They are also the layer this rule's own `why` says a fan-out actually gets
  // written at -- "a tool in src/mcp/tools/ never sees a tsdav call, only
  // getEvent or searchContacts". The four service write entry points closed the
  // layer beneath this one; these close this one.
  // `combinator(ids.map((id) => buildDeletePreview(...)))` -- "preview deleting
  // all of these" -- is the shape, and it did not fire.
  //
  // All three `Preview` names need their own entry: `buildPreview` is not a
  // prefix of `buildCreatePreview` or `buildDeletePreview`, so the prefix
  // relation described for `getEventWithEtag` below does NOT apply to them and
  // none of the three covers either of the others. That is asserted rather than
  // claimed -- test/forbidden-tokens.test.ts checks the whole alternation for
  // names matched through another entry and pins the exact list of exceptions.
  //
  // `getEventWithEtag` is named for legibility and for the set-equality in
  // test/forbidden-tokens.test.ts, NOT because the pattern needs it: `getEvent`
  // precedes it in the alternation and is a prefix of it, so the name already
  // matched before it was written down. Its per-name loop assertion is
  // therefore redundant by construction and cannot fail; the set-equality is
  // what actually holds it here. Recorded rather than repaired, because the
  // repair -- a trailing word boundary on the group -- would make this rule
  // match strictly LESS than it does today, and narrowing a safety rule to
  // tidy an assertion is the move the Conventions forbid outright.
  //
  // `buildContactUpdatePreview` is phase 16's last composite and it is named on
  // exactly the same footing. It ends in TWO of the names beside it -- the
  // read-with-a-version and the duplicate scan -- which makes it two temptations
  // rather than one, and makes "covered by accident" twice as easy to arrive at:
  // a body that stopped calling either one would still match through the other,
  // and the guarantee would be resting on which of the two survived the refactor.
  // It contains no existing entry as a substring, so its per-name loop in
  // test/forbidden-tokens.test.ts can genuinely fail and the recorded
  // prefix-shadow exception list does not grow.
  //
  // Phase 18's three conflict composites (18-REVIEW WR-05) are named on the
  // same footing: `conflictsFor`, `seriesConflictsFor` and `sweepOrDegrade`,
  // each ending in `findWindowConflicts` and each containing no listed name, so
  // a combinator over any of them passed this rule until they were written
  // down. Each needs its own entry. The review that filed them expected
  // `conflictsFor` to cover `seriesConflictsFor`, but this pattern is
  // case-sensitive and the series name spells `ConflictsFor` with a capital,
  // so neither shadows the other and the prefix-shadow exception list in
  // test/forbidden-tokens.test.ts stays at two.
  //
  // The structural half remains the per-request serialisation gate in
  // `src/dav/transport.ts`, which is what independently held the connection
  // budget while this rule's reach was short of its claim.
  //
  // Same statement-bounded span as the two rules above, for the same reason the
  // comment at the top of this section gives: the realistic fan-out is
  // `combinator(calendars.map((c) => fetchCalendarObjects(...)))` and the arrow
  // function's own `()` would end a `[^)]*` span before the guarded call was
  // ever reached.
  {
    id: "dav-concurrent-request",
    scope: "src/",
    pattern:
      /\bPromise\.(?:all|allSettled|any|race)\s*\([^;]{0,400}?(?:davFetch|createAccount|propfind|fetchCalendars|fetchCalendarObjects|calendarQuery|calendarMultiGet|fetchAddressBooks|fetchVCards|addressBookQuery|addressBookMultiGet|supportedReportSet|createCalendarObject|updateCalendarObject|deleteCalendarObject|makeCalendar|davRequest|deleteObject|withRediscovery|resolveDavAccount|resolveOrganizerAddress|pagedEvents|listCalendars|listEvents|searchEvents|getEvent|listAddressBooks|searchContacts|getContact|runDavDiagnosticOutcome|createEvent|updateEvent|deleteEvent|getEventWithEtag|applyCommit|buildPreview|buildDeletePreview|buildCreatePreview|occurrenceBody|scopelessBody|applyNarrowedDelete|observeDelivery|findFreeSlots|collectFrom|runCollectionWriteProbe|runTaskCollectionProbe|runPropertyNameProbe|createVCard|createContact|buildContactCreatePreview|applyContactCommit|findDuplicateCandidates|updateVCard|getContactWithEtag|updateContact|buildContactUpdatePreview|createCalendarCollection|updateCalendarCollection|readCollectionState|resolveDefaultCalendarUrl|deleteCalendarCollection|buildCollectionDeletePreview|applyCollectionCommit|resolveCalendarUserAddresses|buildReplyPreview|applyReplyCommit|findWindowConflicts|conflictsFor|seriesConflictsFor|sweepOrDegrade|syncCollection|calendarChangesSince|syncOneCalendar|fetchCollectionStates|changedEventRows|reportOutcome)/g,
    why: "A concurrent combinator wrapped around a DAV request, or around one of the service entry points that ends in one. The platform cap is not the reason: workerd queues a seventh simultaneous connection until one of the six receives its response headers, so exhausting that budget costs latency rather than an error. The reason is iCloud's own per-account ceiling, which is lower, undocumented, and deliberately unmeasured -- because exhausting it does not fail politely, it locks the user out of their own mail in Mail.app on their own devices. The entry points are named as well as the library primitives, and the scope is the whole of src/, because that is where a fan-out is actually written: a tool in src/mcp/tools/ never sees a tsdav call, only getEvent or searchContacts, and even a single-calendar listing is already three serial round trips before anything multiplies it -- it was nineteen while an account-wide listing existed, and that form was withdrawn precisely because the sweep could not be repaired by making it concurrent. The WRITE entry points are named alongside the reads, and they are the sharper case: a read that loses the race returns a worse answer and leaves the calendar alone, while a half-completed fan-out over writes leaves a state nobody chose, that no retry can describe, and that cannot be put back. The COMPOSITE tool-layer entry points are named alongside both -- the three preview builders, the commit, the narrowed delete, the occurrence patch and the delivery observation -- because each of them ends in one or more of the names beside it and each was therefore covered only by accident, which is how a guarantee quietly leaves when a body is refactored; they are also, by this rule's own reasoning above, the exact layer a fan-out gets written at. Phase 6 (SCHED-01) adds findFreeSlots and collectFrom: findFreeSlots is the new orchestrator that sweeps every calendar the account has for free/busy time, exactly the account-wide shape D-84 reintroduces, and collectFrom is now called in a loop over collections for the first time -- pagedEvents called it once per request, so it carried no fan-out risk and was correctly absent before, and the temptation to wrap that new loop in a combinator is the precise Pitfall 3 this extension closes. This rule bans CONCURRENCY and not request count -- the two-request serial commit a scoped calendar change deliberately pays is permitted, because a patch needs the whole resource and rebuilding drops every component it did not rebuild. tsdav additionally fans out INSIDE its own fetchCalendars and fetchAddressBooks, in a directory this scanner cannot walk, which is why the structural half of the guarantee is the per-request serialisation gate in src/dav/transport.ts rather than anything visible at a call site; this is the detective half. Phase 14 (SPIKE-02, SPIKE-04) adds makeCalendar, davRequest and deleteObject as library primitives and runCollectionWriteProbe and runTaskCollectionProbe as service entry points, for the two reasons this text already separates. The write probe creates, renames, recolours and deletes a throwaway collection, so a fan-out over it is precisely the half-completed state the WRITE paragraph above calls the sharper case -- except worse, because the half-completed state here is a COLLECTION left on the account rather than an event, and the probe's own cleanup verification is what a combinator would race. The to-do listing is the shape this rule was written for outright: a loop over collections, one calendar-query per collection, which is exactly where a combinator gets written because it is what makes N round trips fast -- the same temptation collectFrom's loop introduced one phase earlier. Phase 16 (CONW-01) adds createVCard as a library primitive and createContact, buildContactCreatePreview and applyContactCommit for the two reasons this text already separates. A contact write is ONE card per request, and a fan-out over contact writes is the same half-completed state the WRITE paragraph above calls the sharper case -- 'add all of these people' is one sentence, and what it leaves behind on a partial failure is an address book holding some of a list nobody can name. The two composites are named beside the service entry point on the COMPOSITE paragraph's own terms: each ends in one or more of the names beside it, so each would be covered only by accident, and a body is a refactor away from not doing that. Phase 16 (CONW-05) adds findDuplicateCandidates, and it is the case this rule's own text describes most directly: two probes over one address book is exactly the loop somebody wraps in a combinator, because that is what makes two round trips fast, and the concurrent version returns the same candidates -- so nothing about the answer would reveal it. It needs no new library primitive, because every request it issues is already named beside it: the filtered query, the enumeration and the bulk read. It is also the one entry point here whose whole purpose is advisory, which makes it the easiest to justify speeding up and the least likely to be noticed doing so. Phase 16 (CONW-02, CONW-06) adds updateVCard as a library primitive and getContactWithEtag and updateContact as service entry points, for the two reasons this text already separates. An UPDATE is one card per request, and its read and its write are two SERIAL awaits rather than a pair to be raced -- the read is what produces the version stamp the write is conditional on, so racing them is not merely a connection-budget problem, it is asking the server about a version nobody has read yet. A fan-out over updates is the same half-completed state the WRITE paragraph above calls the sharper case, and worse than the create's: 'fix everyone's job title' leaves an address book in which some cards were overwritten and the rest were not, and the ones that were cannot be put back. A multi-collection operation must be serial. Phase 16 (CONW-02) adds one more composite, buildContactUpdatePreview, on the COMPOSITE paragraph's own terms: it ends in getContactWithEtag AND in findDuplicateCandidates, so it is two ways to be tempted into a combinator rather than one, and it would be covered only by accident through whichever of the two a later body still happened to call. Its two awaits are serial on purpose and the order is load-bearing: the card is read first so the scan can be told which card to leave out of its own answer. Phase 17 (CALM-04) adds createCalendarCollection, and it is the first entry point on this list whose SUBJECT is a collection rather than something inside one. The temptation this phase introduces has a shape the earlier ones did not: an account holds nine calendars, and once one of them can be made, renamed or removed by name, 'tidy up my calendars' is one sentence that means N of them -- and the first thing anybody reaching for that writes is a combinator, because that is what makes N round trips fast. Every one of those round trips is a DAV request against the same account. iCloud's own per-account ceiling is lower than the platform's six, undocumented, and deliberately unmeasured, because exhausting it does not fail politely: it locks the user out of their own mail in Mail.app on their own devices. It is also the WRITE paragraph's sharper case taken one level up -- a half-completed fan-out over collections leaves whole calendars nobody chose, some made and some not, and on the rename and delete that follow in plans 17-04 and 17-06, some gone. A multi-collection operation must be serial. It needs no new library primitive: davRequest, the raw request helper this create assembles its extended MKCOL through, has been on this list since phase 14. Phase 17 (CALM-06) adds readCollectionState, the collection count entry point, and the temptation it creates is the most natural fan-out in this phase precisely because it is a READ, which is what makes it easy to justify: 'which of my calendars are empty' is one sentence that means one depth-1 PROPFIND per calendar, the combinator is what makes nine round trips fast, and the concurrent version returns the same counts so nothing about the answer would reveal the change. A multi-collection count must be serial. Phase 17 adds resolveDefaultCalendarUrl, and it is on this list on the COMPOSITE paragraph's own terms rather than for a new request shape: the function ENDS in propfind, so leaving it off would leave it covered only by accident, and the accident evaporates the first time its body is refactored -- which is exactly how buildContactUpdatePreview and the collection composites above are argued. The shape it ships is the sharp one. It is TWO serial PROPFINDs inside one function, principal then scheduling inbox then default calendar, and that is the pair somebody wraps in a combinator because that is what makes two round trips fast; the concurrent version returns the same URL, so nothing about the answer would reveal the change; and the second request needs the first's answer, so racing them is not merely a connection-budget problem, it is asking about an inbox nobody has resolved yet. THE ENTRY IS NOT ARM-SPECIFIC AND MUST NOT BE READ AS LEFTOVER FROM A BRANCH THAT DID NOT SHIP. A measurement against the real account chose between two already-decided implementations of this function, and the other one carried ONE request rather than two -- a weaker temptation, and registered on exactly the same footing, because which arm shipped is a fact about a checkpoint answer rather than a fact about whether a later session can fan this out. A registration that held against the two-request body and not the one-request body would be a registration resting on which arm a reader remembered. IT ALSO SURVIVED THE WITHDRAWAL OF THE REQUIREMENT IT ARRIVED FOR. CALM-07 was withdrawn on 2026-09-26 because the property this function asks for does not exist server-side, and the function was KEPT anyway -- it is the instrument that took that measurement and dav_diagnose still reports what it reads, so it still issues its two serial PROPFINDs and is still the pair somebody would race. Phase 17 (CALM-06) adds deleteCalendarCollection as the DAV entry point and buildCollectionDeletePreview and applyCollectionCommit as the two tool-layer composites, and this is the most expensive fan-out in the phase to get wrong rather than merely the newest. A caller asked to tidy up several calendars is the most natural multi-collection sentence anybody will ever type at this server -- \"get rid of these three\" -- and the first thing anybody reaching for it writes is a combinator, because that is what makes three round trips fast. Every parallel leg is a DESTRUCTIVE request against the same account, which is the WRITE paragraph's sharper case taken as far as it goes: a half-completed fan-out here leaves whole calendars gone that nobody chose, and every event, to-do and unparseable resource inside each of them, with no answer that can say which and no retry that can put any of it back. iCloud's per-account ceiling is lower than the platform's six, undocumented, and deliberately unmeasured, so a fan-out cannot even be sized before it is attempted. A multi-collection delete must be serial, and there is no batch shape that makes it safe -- doing LESS work is the answer rather than doing the same work faster. The two composites are named on the COMPOSITE paragraph's own terms and each ends in more than one name beside it: the preview ends in resolveDavAccount and readCollectionState, and the commit ends in readCollectionState AND deleteCalendarCollection, so each would be covered only by accident and by whichever of its calls a later refactor happened to keep. The commit's three requests -- the binding re-read, the removal, and the fresh look that verifies it -- are serial on purpose and the order is load-bearing twice over: the re-read is what decides whether the removal is sent at all, and the fresh look is the only evidence this project accepts that the removal landed, so racing either with the removal would be asking about a collection nobody has decided to delete yet or looking before the delete arrived. It needs no new library primitive: deleteObject, the helper the removal is issued through, has been on this list since phase 14. Phase 17 adds runPropertyNameProbe, the third `dav_diagnose` probe, and it is on this list for the reason the probes beside it are rather than for a new request shape: it ends in davRequest, which has been on the library half since phase 14, so it matched by ACCIDENT before it was written down and the accident evaporates the first time its body is refactored. The shape it ships is the one this rule was written for outright. It is a LOOP over four resources -- the principal, the calendar home, the scheduling inbox and one calendar -- issuing one depth-0 `DAV:propname` PROPFIND apiece, which is exactly where a combinator gets written because that is what makes four round trips fast, and the concurrent version returns the same four property-name lists so nothing about the answer would reveal the change. Being a READ is what makes it easy to justify speeding up, exactly as readCollectionState's entry above records: it writes nothing, so a fan-out here costs no calendar state -- but every leg is still a socket against one account, iCloud's own per-account ceiling is lower than the platform's six, undocumented and deliberately unmeasured, and exhausting it locks the user out of their own mail in Mail.app on their own devices. Four round trips plus discovery and the home listing is already most of one invocation's budget before anything multiplies it. propertyNamesInBody is NOT on this list, for the reason every pure reader here is left off: it reads element names out of the raw multistatus BODY the probe already holds and issues no request. That clause named isDefaultCalendar as its precedent until 2026-09-26, when CALM-07's withdrawal deleted that function; a precedent citing a name that no longer exists is a reason a reader cannot check. It reads the body rather than the library's parse because that parse could not answer the question at all -- a defect measured live on 2026-09-25 and recorded in its own section in src/dav/diagnose.ts -- and the swap changes nothing about this rule's reasoning, because a reader of a string issues no more requests than a reader of an object. It carries no manifest disposition either, and that is correct rather than an omission -- it is module-private, and the manifest collects `export function` declarations, so a name that is not exported is not a name the tool layer can reach. Phase 18 (RSVP-01, RSVP-04) adds resolveCalendarUserAddresses, the read of the account's whole calendar-user address set, and buildReplyPreview and applyReplyCommit, the two tool-layer composites that answer an invitation. Each ends in DAV round trips against one account. The address read is ONE PROPFIND at the principal, and it now runs on every answer's preview AND commit as well as on the invited create, so it is the name a sweep reaches for: 'what did I answer to everything this week' is one sentence that means one read per invitation, and a combinator is what makes that fast. The preview ends in the event read and the address read; the commit ends in the event read, the address read and the one conditional write. Their awaits are serial on purpose and the order is load-bearing: the event read brings back the ETag the write is conditional on, and racing the write against the read that decides whether it may be sent is asking about a resource nobody has read yet. A fan-out over answers is the WRITE paragraph's sharper case with one more thing that cannot be taken back: each answer may make iCloud send a reply to a real person, and 'accept all of these' half-done leaves some organisers told and some not, with no answer that can say which. A multi-invitation answer must be serial. It needs no new library primitive: every request these three issue is already named beside them. Phase 18 (RSVP-03) adds findWindowConflicts, the sweep that finds what else is on the calendar in an invitation's window, and it is findFreeSlots' own shape run a second time: one enumeration, then collectFrom once per calendar in a plain serial loop, on every answer's preview -- the loop a combinator gets wrapped around because that is what makes nine round trips fast, and the concurrent version finds the same conflicts so nothing about the answer would reveal the change. Phase 18's code review (WR-05) adds the three tool-layer composites that end in that sweep -- conflictsFor for a one-off invitation, seriesConflictsFor for a series, and sweepOrDegrade, which both call -- on the COMPOSITE paragraph's own terms: none of them contained a listed name, so a combinator over them passed this rule outright, and 'check what clashes with each of these invitations' is one sentence that means one whole account sweep per invitation. Phase 23 (CHNG-01, D-32) adds syncCollection as a library primitive and calendarChangesSince, syncOneCalendar and fetchCollectionStates as service entry points, and the change check is this rule's shape in its plainest form. It is a loop over every calendar the account has: one PROPFIND at the home for every token, then one sync REPORT for each calendar whose token moved, one after another. That loop is exactly what a combinator gets written around, because that is what makes nine round trips fast, and the concurrent version returns the same counts -- so nothing in the answer would reveal it. It is also a check the user may run several times a day, which makes the cost of a fan-out a daily cost rather than an occasional one. syncOneCalendar is module-private and named anyway: it is the step the loop repeats, and the per-calendar step is where a refactor would put the combinator. readSyncAnswer is NOT on this list, for the reason every pure reader here is left off: it reads responses the caller already holds and issues no request. Phase 23 (D-26) adds changedEventRows, the one calendar-multiget per changed calendar that reads the event rows, and reportOutcome, the step that sends one sync REPORT and sorts its failure. Both are module-private and named anyway, on the COMPOSITE paragraph's terms: each is called once per calendar inside the loop, so the per-calendar step is where a refactor would put the combinator, and the concurrent version returns the same rows and counts. eventChangeFactsOf is NOT on this list: it parses bytes the caller already holds and issues no request.",
  },
  // D-55's account-discovery call takes two boolean flags that quietly change
  // its cost class. Banned rather than reviewed, because the cost is invisible
  // at the call site: the flag reads like a convenience.
  {
    id: "dav-eager-load",
    scope: "src/dav/",
    pattern: /\b(?:loadObjects|loadCollections)\b/g,
    why: "A tsdav account-discovery flag that turns one PROPFIND into a fan-out over every collection on the account -- and the object-loading one additionally fetches every object inside each of them. That is a request-count problem and a response-size problem in a single boolean, on an account with nine calendars, and neither cost is legible at the call site. Discovery resolves the home URL and stops there; collections are enumerated deliberately, by the code that knows how many of them it actually needs.",
  },

  // ----------------------------------------------------- unsendable method
  // D-15, Phase 17. The only pair on this list banning something this project
  // cannot do rather than something it must not do -- and the reason it is a
  // ban rather than a note is that the platform's refusal is INVISIBLE at the
  // call site and arrives wearing another failure's clothes.
  //
  // Neither entry carries a `scope`. That is the owner's 2026-09-25 ruling and
  // an absent `scope` is what makes the ban blanket: every root in
  // `SCAN_ROOTS`, `src/`, `scripts/` and `test/` alike. A narrower scope was
  // offered and declined, and a file exclusion was refused outright -- see the
  // `EXCLUDED` docstring below for why an exclusion is the more expensive
  // answer than it looks.
  {
    id: "mkcalendar-method",
    pattern: /\bMKCALENDAR\b/g,
    why: "The RFC 4791 calendar-creation method, which this runtime cannot express at all: `new Request(url, { method: \"MKCALENDAR\" })` throws `TypeError: Invalid HTTP method string` inside workerd's own method validation, while `PROPFIND`, `PROPPATCH`, `REPORT`, `MKCOL`, `DELETE` and `PUT` are all accepted. The request is never built, so no byte leaves the Worker and no server ever sees it. That would be harmless if it failed honestly, and it does not: the `TypeError` is raised inside `createDavFetch`'s `try` around the fetch, which mapped every caught value to `DavConnectError`, and `davToErrorCategory` defaults that to `connection_failed` -- so the caller was told \"Could not establish a secure connection to iCloud Mail. This may be transient -- safe to retry once\", and every clause of that was false. No connection was attempted, nothing was transient, and no retry could ever work. This is MEASURED rather than hypothetical: it is what SPIKE-04's first live probe run actually reported to the owner on 2026-09-24, against the real account, and that report was on its way into a written verdict about what iCloud does with collection writes when it was a fact about what Cloudflare does with a method string. The route this project takes instead is RFC 5689 extended `MKCOL`, which expresses the same intent with a method this platform will send. A LEGITIMATE mention -- a docstring explaining the constraint, a test constructing the string to prove the runtime still refuses it -- is fixed AT THE SOURCE, by building the string from fragments or by naming the method by its role, exactly as `src/mail/socket.ts` already does for the banned transport paths. It is never fixed by narrowing this pattern and never by adding a file to EXCLUDED: ./.claude/CLAUDE.md's Enforcement section is explicit that exclusion is by PATH and never by making a rule see less, and EXCLUDED is all-rules-per-file, so skipping a file here silently drops its fan-out, logging, host-literal and read-only coverage too.",
  },
  {
    id: "tsdav-make-calendar",
    pattern: /\bmakeCalendar\b/g,
    why: "The DAV library's collection-creation helper, which hardcodes the method the rule above bans. It is therefore unusable from this platform no matter what iCloud would accept -- the throw happens in the `Request` constructor, before anything is sent, so its behaviour against a real server is unmeasurable from this runtime and cannot be established by trying. `src/dav/diagnose.ts` deliberately does NOT import it, and the collection create in this project is a hand-rolled RFC 5689 extended `MKCOL` assembled through the library's raw request helper instead. This name is ALSO one of the names on the `dav-concurrent-request` alternation above, and that is intentional rather than a duplicate to be tidied away: the alternation fires only on a concurrent combinator wrapped around the name, while this rule fires on the name appearing at all. The two answer different questions and neither one covers the other, so do not remove it from the alternation and do not remove this rule because the alternation already mentions it -- the alternation entry is what keeps a future call site guarded by the containment gate's vocabulary the moment one appears.",
  },

  // ------------------------------------------------------------------ time
  // The one rule here that is not about a request budget. It is on this list
  // rather than in a review checklist because its failure mode is silence: no
  // exception, no failing assertion, just times that are wrong by the offset
  // between two machines.
  {
    id: "ical-jsdate",
    scope: "src/dav/",
    pattern: /\.toJSDate\s*\(/g,
    why: "The parsed-time conversion to a host-runtime date. The value it produces depends on the host machine's timezone, and the two hosts disagree: the vitest pool inherits the developer's zone while production runs UTC. The failure is not an error but silently wrong times -- so the bug passes the suite locally and is wrong for the user, which is the worst shape a bug can have in a calendar. Resolve the zone first and then read the seconds-since-epoch accessor, which is absolute and is the permitted form.",
  },

  // ---------------------------------------------------------------- read-only
  // D-47. The convention half of "Claude reading your mail is not you reading
  // your mail". The structural half is that every mailbox opened on a READ
  // path is opened read-only, which makes the mutation refusable by the server
  // for a whole session. Phase 20 added one separate mutating path, used only
  // by explicit triage verbs, and it fetches no message body at all.
  //
  // Anchored on the fetch-item context rather than on the spelling alone, and
  // that is precision rather than leniency: the server spells the RESPONSE key
  // for a peeking fetch without the peek, so an unanchored rule would ban
  // reading the reply to the very command it exists to protect. Two anchors,
  // because a fetch item list is written both ways here -- inline in a FETCH
  // command, and hoisted into a `"(...)"` constant. `\bFETCH` carries no
  // trailing boundary on purpose, so a `FETCH_ITEMS`-style identifier anchors
  // it too.
  //
  // Bounded by the LINE as well as by the statement. A fetch item list is one
  // line everywhere in this codebase, while the parser's ABNF docstrings quote
  // a bare `"("` several times within a few lines of a section-specifier
  // example -- a multi-line span would report those and nothing else.
  //
  // The optional `(?:\.\w+)?` qualifier is what makes the negative lookahead
  // LOAD-BEARING rather than decorative, and this was measured: without the
  // qualifier the lookahead is dead, because the character it guards against is
  // a dot and the only character that may follow is a bracket. A mutation run
  // deleting the lookahead left the suite green, which is exactly the "a rule
  // that silently matches nothing looks like a rule that was never added"
  // failure the coverage assertion exists to catch -- one level down, inside a
  // rule that does fire.
  //
  // `RFC822` and `RFC822.TEXT` are the same hazard under a different spelling:
  // RFC 3501 makes them functionally equivalent to the bare body item, seen-flag
  // side effect included. `.SIZE` and `.HEADER` are excused because neither
  // fetches body content and neither sets the flag -- `.SIZE` is in this
  // project's own permitted item list.
  //
  // Case-insensitive because the protocol is: a server treats a lowercase item
  // name as the same item, so a lowercase spelling is the same violation.
  {
    id: "non-peeking-fetch-item",
    scope: "src/",
    pattern:
      /(?:\bFETCH|["'`]\()[^;\n]{0,120}?\b(?:BODY(?!\.PEEK)(?:\.\w+)?\[|RFC822(?!\.(?:SIZE|HEADER))\b)/gi,
    why: "A body fetch item written without the peeking form (or its RFC822 synonym, which RFC 3501 makes functionally equivalent). Fetching this way sets the seen flag as a side effect, and the page-listing path touches every message on a page -- so one slip marks a whole page read in a single call, and read status is a field the user relies on. The structural half of the guarantee is that every mailbox opened on a read path is opened read-only, so the server refuses the mutation for the whole session, and the one mutating path fetches no body at all; this rule is the convention half, and it catches the slip before it reaches a server that might not refuse it. Reading the server's reply is unaffected: the response key is spelled without the peek, which is why this rule is anchored on the fetch item list rather than on the spelling alone.",
  },

  // ------------------------------------------------------------- store scoping
  // ISO-06, D-13, D-21. Phase 10.
  //
  // THE RULE. Every KV and R2 key this project writes belongs to exactly one
  // person. The staging bucket holds that person's attachments, the confirm
  // namespace holds their pending writes, and the DAV cache holds their
  // account's home URLs. So a key expression built under `src/` from a key
  // prefix constant must put the user id straight after that constant, and
  // nothing else may sit between the two.
  //
  // WHY THIS SHAPE, AND NOT THE LITERAL READING OF D-13. D-13 says "a key
  // prefix constant declared under src/ that carries no user segment". Read as
  // "the constant's own value must contain a user id" that is unsatisfiable: a
  // module-scope constant is evaluated once when the isolate boots and there is
  // no user then. ISO-06's own wording says a key **built** under `src/`, and
  // that is the readable version: a USE of a prefix constant in a key
  // expression that does not put a user id straight after it. Anchoring on the
  // prefix constants is also how the rule finds a key expression at all. A rule
  // over every string that merely looks like a key would fire on test data, on
  // comments, and on the OAuth library's own documented key shapes, so it does
  // not exist.
  //
  // WHY A KEY WITHOUT A USER SEGMENT IS THE FAILURE. It is a key any signed-in
  // caller can name. One person's object becomes reachable through another
  // person's request, and nothing fails on the way in -- the store returns the
  // object it was asked for, which is exactly what it is built to do.
  //
  // WHAT IT DOES NOT SEE. Every one of these builds a key with no user id and
  // fires nothing:
  //
  //   1. concatenation instead of a template: `CONFIRM_KEY_PREFIX + jti`;
  //   2. a key built from a bare literal at the call site, with no prefix
  //      constant at all;
  //   3. a prefix constant renamed so it no longer ends in `PREFIX`, or no
  //      longer contains one of the eight store words;
  //   4. the user id interpolated under another name -- `${who}`, `${uid}`.
  //      The rule keys on the spelling `userId`, optionally behind up to three
  //      member accesses, so `${userId}`, `${actor.userId}` and
  //      `${principal.userId}` are the three live spellings and all three pass;
  //   5. the prefix constant copied into a variable first: `const p =
  //      CONFIRM_KEY_PREFIX;` and then `` `${p}${jti}` ``;
  //   6. the OAuth library's own keys (`grant:`, `token:`, `client:`), which
  //      live in `node_modules`, outside every entry in `SCAN_ROOTS`.
  //
  // A rule believed to prove more than it does is worse than one whose limits
  // are written down.
  //
  // ONE ENTRY LEFT THIS LIST IN PHASE 11, and the departure is recorded rather
  // than silently dropped. The login failure counter in `src/auth/login-handler.ts`
  // used to be keyed by the connecting SOURCE and built from bare literals, so
  // this rule could not see it at all; the list said so, and told Phase 11 not
  // to assume otherwise. Phase 11 re-keyed that counter to the TARGET's derived
  // user id behind a prefix constant, so this rule now does see it, and it
  // passes because the id sits immediately after the prefix. Audit row S5. It
  // is the first thing under `src/auth/` this rule has ever reached.
  //
  // THE SHAPE. An interpolation whose whole content is an upper-case identifier
  // containing one of eight store words and ending in `PREFIX`, NOT followed by
  // an interpolation of `userId` with at most one member access in front of it.
  //
  // THE LOOKAHEAD STARTS ON THE VERY NEXT CHARACTER, and that is load-bearing
  // rather than terse. It carried a leading `\s*` when it was written, which is
  // outside the interpolation and therefore matches LITERAL characters of the
  // template: `` `${CONFIRM_KEY_PREFIX} ${userId}:${jti}` `` passed, and so did
  // the same thing with a newline. Both build a key with a space or a newline
  // between the prefix and the id — not the key this rule says is required. The
  // concrete bytes were spelled here with the confirmation prefix's version
  // segment in them and went stale when that prefix moved, so the shape is
  // described rather than quoted. No
  // cross-user leak, since the id is still there, but the rule proved less than
  // its own first paragraph claimed, and that paragraph is the thing a reader
  // relies on. Dropped, so anything at all between the prefix and the id fires.
  // This only ever refuses more. `test/forbidden-tokens.test.ts` carries the
  // space and newline cases as must-fire rows so the gap cannot reopen quietly.
  //
  // THE MEMBER-ACCESS CHAIN IS BOUNDED AT THREE, NOT AT ONE, AND THE REASON IS
  // THE FAILURE MODE RATHER THAN TASTE. At one, a perfectly correct key written
  // `` `${STAGING_PREFIX}${ctx.actor.userId}/...` `` FIRED. `.husky/pre-commit`
  // runs under `set -e`, so a false positive here does not refuse one line: it
  // refuses every commit in the repository, including commits on work that has
  // nothing to do with keys — which is the failure D-21 and the armed-last
  // ordering exist to avoid, arriving later and by a different door. Widening
  // the chain admits nothing a one-deep chain did not already admit: the
  // literal spelling `userId` is still required at the end, so a key with no
  // user in it fires exactly as before. It is bounded rather than left open for
  // the reason both upper-case runs are bounded, and measured on the same
  // 200,000-character adversarial input.
  //
  // A DEEPER OR COMPUTED PATH IS STILL A FALSE POSITIVE, and the remedy is to
  // bind the id to a local first -- `const userId = a.b.c.d.userId;` -- rather
  // than to widen this rule again. A call in the path, `${resolve(x).userId}`,
  // is the same case and the same remedy.
  // Both upper-case runs are bounded at 40 rather than left unbounded: that is
  // what makes a 200,000-character adversarial input return in 0 ms, and it is
  // not a tidiness knob. The MIME boundary constant in the message-assembly
  // module is the near-miss, and the store-word filter is what keeps it clean
  // WITHOUT a path exclusion -- an exclusion there would drop the logging,
  // fan-out and write rules on that module too.
  //
  // ARMED LAST, ON PHASE 9'S PRECEDENT. It fired on four real lines when Phase
  // 10 opened. `.husky/pre-commit` runs under `set -e`, so arming it before all
  // four key expressions were reshaped would have refused every commit in the
  // repository, including commits on unrelated work. It landed on a tree where
  // it refuses nothing.
  //
  // ONE CONSEQUENCE WORTH KNOWING. The DAV cache key was reshaped by moving a
  // colon out of the key expression and into the prefix constant (D-20). That
  // change alters no byte of the key, so NO TEST IN THIS REPOSITORY CAN SEE IT
  // -- measured, with all 2838 tests green either way. This rule is the only
  // thing holding it. If somebody moves the colon back, the suite stays fully
  // green and this rule starts refusing every commit, and the two events will
  // look unrelated.
  {
    id: "store-key-without-a-user",
    scope: "src/",
    pattern:
      /\$\{\s*[A-Z0-9_]{0,40}(?:KEY|KV|CACHE|STAGING|CONFIRM|BUCKET|R2|STORE)[A-Z0-9_]{0,40}PREFIX\s*\}(?!\$\{\s*(?:[A-Za-z_][A-Za-z0-9_]{0,40}\s*\.\s*){0,3}userId\s*\})/g,
    why: "A store key built under src/ from a key-prefix constant with no user id straight after it. Every KV and R2 key this project writes belongs to exactly one person -- the staging bucket holds their attachments, the confirm namespace holds their pending writes, the DAV cache holds their account's home URLs. A key with no user segment is a key any signed-in caller can name, so one person's object becomes reachable through another person's request, and nothing fails on the way in: the store returns the object it was asked for. Interpolate the user id straight after the prefix constant, and take it from the signed-in principal -- never from the key, the token or the id being checked, because those are caller-supplied and a caller who chooses the segment chooses whose data to read. If this fired on something that is not a store key, rename the constant so it no longer reads as one. Do not buy it off with a path exclusion: this scanner's skip list is per file and not per rule, so excluding one file here would silently drop the logging, fan-out and write rules on it as well.",
  },

  // THE RULE. The one-time reservation for a confirmation is keyed on the
  // CALLER's own user id and on nothing else. This rule bans the one
  // alternative a reader is actually tempted by: the id carried inside the
  // confirmation payload, reached as a `.u` member in the reservation's own
  // argument list.
  //
  // WHY THE TWO ARE NOT INTERCHANGEABLE, EVEN THOUGH THEY ARE ALWAYS EQUAL.
  // Audit row T1 is closed by TWO layers, and this is the second of them
  // (D-12, corrected by measurement in plan 10-04). Layer one is the user
  // check inside `verifyConfirmation`, which refuses a caller presenting
  // somebody else's confirmation. Layer two is this key: a caller who ever
  // reached the reservation holding somebody else's confirmation burns a slot
  // under their OWN id, so the owner's confirmation still spends. Reading the
  // payload here would collapse layer two onto layer one -- the slot would
  // belong to whoever the token names, which is audit row T1 exactly as it
  // was, where a refused commit spends the owner's slot and the owner must
  // preview again.
  //
  // WHY A RULE RATHER THAN A TEST. No test in this repository can tell the two
  // expressions apart. Layer one guarantees they are equal by the time the
  // reservation runs, so every execution this project can produce agrees.
  // Reaching the reservation with a mismatched pair would need layer one
  // disabled, and the only way to do that from a test is a test-only path into
  // the verifier -- a back door that would cost more than it bought. So the
  // swap is a one-word edit that reads as more correct, removes a layer, and
  // leaves the whole suite green. That is the same hazard class as the D-20
  // colon, and it gets the same answer.
  //
  // WHAT IT DOES NOT SEE. Every one of these makes the swap and fires nothing:
  //
  //   1. the id bound to a local first -- `const u = payload.u;` and then
  //      `reserveConfirmation(kv, u, ...)`;
  //   2. subscript access -- `payload["u"]`;
  //   3. the field renamed from `u` to anything else;
  //   4. an argument list longer than 200 characters, or one carrying a `)`
  //      of its own -- a nested call among the arguments ends the span early,
  //      and the rule then sees nothing past it;
  //   5. the reservation renamed, or reached through a variable.
  //
  // A rule believed to prove more than it does is worse than one whose limits
  // are written down.
  //
  // MEASURED ON THE REAL TREE. 0 hits under `src/` -- the declaration in
  // `src/confirm.ts` and the single call site in `src/mcp/tools/calendar.ts`
  // are both clean, so it is armed on a tree it refuses nothing on. One
  // consequence: the parameter's own documentation in `src/confirm.ts` states
  // the ban by ROLE and never by name, exactly as the transport and write
  // rules require, because a comment spelling the banned member out would fail
  // the check it was trying to explain.
  {
    id: "confirm-reserve-keyed-on-the-token",
    scope: "src/",
    pattern: /reserveConfirmation\s*\([^)]{0,200}\.\s*u\b/g,
    why: "The one-time reservation for a confirmation is being keyed on the id carried inside the confirmation instead of the id of the caller presenting it. Those two values are always equal by the time the reservation runs, because the verifier already refused a mismatch -- which is exactly why this matters: reading the payload here makes the reservation DEPEND on that earlier check instead of standing beside it, and audit row T1 is closed by the two of them standing separately. The reservation keyed on the caller means a caller who ever reached it holding somebody else's confirmation burns a slot under their own id, and the owner's confirmation still spends. Keyed on the token, that caller burns the owner's slot and the owner has to preview their calendar change again -- the original T1 leak, restored by a one-word edit that reads as more correct and that no test in this repository can see. Pass the signed-in principal's user id and nothing else. If this fired on a reservation that genuinely has no caller to key on, that is a change to how confirmations are scoped and needs a decision, not a pattern edit.",
  },

  // ------------------------------------------------------- the record sweeper
  // LIFE-01, phase 12. The configuration in `src/auth/oauth.ts` claimed a scan
  // gate stood behind it. It did not, and a claimed gate is worse than an
  // absent one: the enforcement section of the conventions warns by name that
  // nothing fails when prose stops matching this script. So here is the gate
  // the prose described.
  //
  // WHY THE HELPER IS BANNED RATHER THAN REVIEWED. Its grant sweep deletes
  // grants whose client record has gone. That is precisely the forced logout
  // LIFE-01 removed, arriving by another road: with the client record gone the
  // token endpoint already refuses the refresh as an unknown client (spike S2),
  // and sweeping the grant makes the loss permanent rather than repairable by
  // restoring a registration. The two never-expiring lifetimes above it are
  // held by nothing but a spread's treatment of an `undefined` own key, so the
  // whole of LIFE-01 is three lines that fail SILENTLY when edited. One of
  // those three is now guarded.
  //
  // Scoped to `src/` because that is the only tree that can call it: the
  // library is only constructed there, and `scripts/grants.mjs` reaches the
  // store through wrangler rather than through the provider. A deliberate
  // account-wide sweep, if one is ever genuinely wanted, is a decision -- and
  // the answer to the problem it would be reached for is `prune-clients` in
  // `scripts/grants-core.mjs`, which deletes a client record ONLY when no grant
  // names it and therefore cannot sign anybody out.
  //
  // MEASURED ON THE REAL TREE. 0 hits under `src/` at the time it was added, so
  // it is armed on a tree it refuses nothing on. One consequence, the same one
  // the transport and write rules carry: `src/auth/oauth.ts` must describe this
  // helper by ROLE and never by name, or it fails the check it exists to
  // explain.
  {
    id: "expired-record-sweeper",
    scope: "src/",
    pattern: /\bpurgeExpiredData\s*\(/g,
    why: "The OAuth library's expired-record sweeper is being called. Its grant sweep deletes grants whose client record has gone, which is the forced logout LIFE-01 removed, arriving by another road -- and it is worse than the original, because a registration can be restored while a swept grant cannot. LIFE-01 rests on three lines in src/auth/oauth.ts and every one of them fails silently when edited: the two never-expiring lifetimes are held only by a spread copying an own key whose value is undefined, so deleting either line restores the default expiry with nothing failing on the way out, and this call restores the logout without touching either. If the reason for reaching for this was client records accumulating, the answer is prune-clients in scripts/grants-core.mjs, which deletes a client record only when NO grant names it and so cannot sign anybody out. If a sweep is genuinely wanted, that is a change to the project's login lifetime and needs a decision, not a call.",
  },

  // ------------------------------------------- the read of a deleted binding
  // CUT-01, phase 13. This was a COUNT until 2026-09-23, with `src/principal.ts`
  // named as its one permitted owner: the constructor that turned the account
  // holder's two Worker secrets into a principal. That constructor is gone,
  // deleted in the same commit as this entry, and the platform stops supplying
  // the two bindings behind it.
  //
  // WHY A BAN AND NOT A COUNT ANY MORE. Zero is now the correct number of
  // readers, so the count's `missing` arm could never fire again -- and this
  // project's own enforcement rule is that a constraint whose missing arm
  // cannot fire looks exactly like a constraint that was never added. The count
  // had to become a ban or become a lie about itself. The two are not
  // interchangeable and the direction of the change is one-way: a count asks
  // "exactly these files", a ban asks "no file", and only the second is true
  // once the thing being counted has been deleted.
  //
  // WHY A READ OF A DELETED BINDING IS REFUSED AT ALL. Because the name coming
  // back is the singular identity coming back. Nothing supplies these two
  // values now, so a read of one resolves to nothing and would fail at run
  // time -- but the failure worth preventing is the quiet one, a session
  // reasoning about a single owner again on a server that serves whoever signed
  // in. The compiler is the FIRST check (Phase 9 D-14): the three names left the
  // shared binding type, so a stray reader does not compile, and
  // `test/env-narrowing.test.ts` pins that with expect-error lines. This is the
  // SECOND, and it exists because the compiler sees types while this sees TEXT.
  // A cast, a comment, or a file the typecheck never reaches gets past one and
  // not the other. Neither sees everything.
  //
  // WHY THIS SCOPE. The source tree only. The sentence carries over from the
  // count's docstring unchanged in substance: tests are not a credential path,
  // and the scanner's own test file spells the read verbatim as a sample and is
  // skipped by path for every rule.
  //
  // WHY THE LOGIN GATE'S SECRET IS LEFT OUT (Phase 9 D-28). It is not an Apple
  // credential and it gates the authorize form rather than an account. It was
  // out of the count for that reason and it stays out of the ban for the same
  // one; a row in the scanner's test pins it as a miss so nobody folds it in.
  //
  // WHAT IT DOES NOT SEE, unchanged from the count it replaces: a destructuring
  // of the environment object; an index access with the name written as a
  // string; an alias of the environment object under another name; a
  // narrow-typed parameter under another name; and a cast in parentheses around
  // the environment object, which puts the cast keyword between the name and
  // the dot.
  //
  // THE MEMBER ACCESS MATCHES WHAT `PROPS_READER` MATCHES (code review WR-03),
  // and the scanner's own test file pins the two as equal by reading this
  // pattern back out of the list by id. Keep them identical: a difference
  // between them is a difference nobody decided.
  //
  // MEASURED ON THE REAL TREE, not asserted: 0 hits under `src/` when it was
  // added, so it is armed on a tree it refuses nothing on. One consequence, the
  // same one the transport, write and sweeper rules carry -- `src/principal.ts`
  // and `src/env.ts` are both inside the scope and both used to spell these
  // names, so both now describe the read by ROLE, or they would fail the check
  // they exist to explain.
  {
    id: "mail-secret-read",
    scope: "src/",
    pattern: /\benv\s*(?:[?!]\s*)?\.\s*(?:APPLE_ID|APPLE_APP_PASSWORD)\b/g,
    why: "A read of one of the two deleted account bindings off the environment object, under src/. Phase 13 removed both from the platform and removed the constructor that read them, so nothing supplies either value any more -- this rule replaced the count that used to permit exactly one reader, because with the reader gone that count's missing arm could never fire, and a constraint whose missing arm cannot fire looks exactly like one that was never added. A read here means somebody is identifying the caller from the deployment again instead of from the grant they signed in with, on a server that now serves more than one person. Take the signed-in principal the door already built and read its Apple ID field, or hand the principal to one of the two password owners. If this fired on a comment, describe the read by role -- write \"the account bindings\" and not the spelled read -- which is what src/principal.ts and src/env.ts both do. Do not narrow the pattern, do not rename the environment object to hide the read, and do not fold the login gate's own secret in: that one is not an Apple credential and has its own reader.",
  },
];

/**
 * The socket choke-point is a COUNT constraint, not a pure negative: the
 * specifier is legitimate in exactly one file and must appear nowhere else.
 *
 * A silently-deleted choke-point is as much a failure as a duplicated one, so
 * `scan()` reports a violation when this matches no file at all.
 */
export const SOCKET_IMPORT = /["']cloudflare:sockets["']/;

/** The one file permitted to match `SOCKET_IMPORT`. */
export const SOCKET_OWNER = "src/mail/socket.ts";

/**
 * The fixed iCloud DAV hostnames, enforced as a COUNT for the same reason the
 * socket specifier is -- and for one more.
 *
 * THE RULE. ROADMAP Phase 3: no constant containing a fixed iCloud DAV hostname
 * may be used for anything past the initial discovery PROPFIND. The partition
 * number in a home URL is per-account AND per-service, and Apple has moved
 * accounts between partitions with no notice, breaking previously-working
 * clients account-wide. A hardcoded shard is therefore not a style problem; it
 * is an outage waiting for Apple's next migration, and the account it takes out
 * is the user's own.
 *
 * WHY A COUNT RATHER THAN A SCOPED NEGATIVE. The natural spelling is "ban this
 * literal under src/, except in the one discovery module". This scanner has no
 * per-rule path exemption: `EXCLUDED` skips a file for EVERY rule. Buying the
 * hostname exemption that way would silently drop the logging ban, the fan-out
 * ban and the host-zone date ban on `src/dav/discovery.ts` -- the one module
 * that most needs them, since it is the module holding the credentials' first
 * outbound hop. Adding per-rule exclusion was rejected in favour of the shape
 * this file already has, because the count form is strictly better here anyway:
 *
 * WHAT THE COUNT SEES THAT A NEGATIVE CANNOT. A negative is trivially satisfied
 * by a discovery module that was deleted, renamed, or emptied -- after which
 * nothing resolves a host at all and the codebase no longer works. Zero
 * resolvers is as much a violation as two.
 *
 * Collected from `src/` only. Test files must name both hosts to build fixture
 * URLs against them (`test/dav-discovery.test.ts` does, extensively), and a
 * fixture URL is not a code path. The ban is on a shipped constant.
 */
export const DAV_HOST_LITERAL = /caldav\.icloud\.com|contacts\.icloud\.com/;

/** The one file permitted to match `DAV_HOST_LITERAL`. */
export const DAV_HOST_OWNER = "src/dav/discovery.ts";

/** The tree `DAV_HOST_LITERAL` is collected from. See the docstring above for
 *  why this is not the full scanned surface. */
export const DAV_HOST_SCOPE = "src/";

/**
 * A bare network call, permitted in exactly one module of the DAV tree.
 *
 * The same argument the socket choke-point carries, restated for the transport
 * that replaces the socket one protocol over. Four obligations land on
 * `src/dav/transport.ts` and no other seam can serve any of them: the per-call
 * Basic credential (so no caller ever holds one), the forced manual redirect
 * (so the credential is not forwarded to a redirect target), the status-number
 * classification (tsdav returns `ok: false` rather than throwing), and the
 * per-request serialisation gate. A second module reaching the network directly
 * defeats all four at once, and it defeats them silently -- the code works,
 * right up until a redirect leaks a credential or a fan-out trips iCloud's
 * per-account ceiling.
 *
 * A count rather than a negative, again in both directions: a choke point that
 * was quietly moved, renamed, or emptied guards nothing, and that failure is
 * far easier to miss than a duplicate.
 *
 * Collected from `src/dav/` only: other trees call the network legitimately,
 * and `src/mcp/api-handler.ts` and `src/auth/login-handler.ts` both define a
 * `fetch` method that this pattern would otherwise report.
 *
 * Case-sensitive and boundary-anchored on purpose. `davFetch` -- the injected
 * transport every DAV caller reaches for, and the permitted form -- differs
 * from the global only in case, and `fetchCalendars` / `fetchAddressBooks` /
 * `fetchVCards` merely begin with the same five letters. A pattern that
 * reported those would be switched off within a week.
 */
export const DAV_FETCH_CALL = /\bfetch\s*\(/;

/** The one file under `DAV_FETCH_SCOPE` permitted to match `DAV_FETCH_CALL`. */
export const DAV_FETCH_OWNER = "src/dav/transport.ts";

/** The tree `DAV_FETCH_CALL` is collected from. */
export const DAV_FETCH_SCOPE = "src/dav/";

/**
 * The write command, permitted in exactly one module of the source tree.
 *
 * THE RULE. Convention 2's boundary is that placing a message into the drafts
 * folder is the entire write path, and is deliberately the entire write path.
 * Claude drafts; the human reviews and sends, and that human step is this
 * project's backstop against prompt-injected content in an email reaching an
 * outbound message. A second module issuing this command is a second write path
 * arriving without a decision, and it arrives silently: a second appender looks
 * exactly like the first at every layer beneath it.
 *
 * WHY A COUNT RATHER THAN A SCOPED NEGATIVE. The same argument the host literal
 * two constants up carries, restated for the write. The natural spelling is "ban
 * this command under src/, except in the one service module". This scanner has
 * no per-rule path exemption: `EXCLUDED` skips a file for EVERY rule. Buying the
 * exemption that way would silently drop the logging ban, the session fan-out
 * ban and the peeking-fetch ban on `src/mail/service.ts` -- the one module that
 * most needs all three, since it is the module holding the write.
 *
 * WHAT THE COUNT SEES THAT A NEGATIVE CANNOT. Zero appenders is as much a
 * violation as two. A negative is trivially satisfied by a service module that
 * was deleted, renamed, or emptied, after which this phase's whole capability is
 * gone and nothing says so. That direction is far easier to miss than a
 * duplicate, because nothing fails on the way out: the tests that covered the
 * deleted code are deleted with it.
 *
 * WHAT IT DOES NOT AND CANNOT SEE. The mailbox is a variable, not a literal, so
 * this rule guarantees ONE APPENDER and cannot guarantee ONE DESTINATION. The
 * destination is held one layer up instead, by plan 04-03's byte-exact assertion
 * on the command line recorded through the in-memory duplex -- discriminating
 * exactly where a regex is not, because it reads the mailbox that was actually
 * written rather than the shape of the line that wrote it. Two further shapes
 * are outside this pattern's reach: a command line carrying a literal tag rather
 * than an interpolated one, and the command word held in a variable and handed
 * to the generic sender in `src/mail/imap-session.ts`. Both are evasions rather
 * than accidents, and this rule is aimed at the accident. Naming the gaps here is
 * what stops a later reader believing the rule proves more than it does.
 *
 * PROSE DISCIPLINE, FOR EVERY MODULE ADDED TO `src/` AFTER THIS RULE. The scope
 * is the whole source tree and the walk happens on every commit, so a comment in
 * a module written months from now is scanned by this rule too. ./.claude/CLAUDE.md
 * § 1 records the hazard in its own words: a source comment spelling a banned
 * token out would fail the very check it was trying to explain. So describe this
 * command BY ROLE -- "the write", "placing the message into the drafts folder",
 * "a write that failed must not delete" -- and never by name, exactly as
 * `src/mail/socket.ts` describes the banned transport paths by role and points
 * here for the spelling. Do NOT rely on this pattern being case-sensitive and a
 * comment happening to be lowercase: that is luck rather than a guarantee, and
 * the failure it produces is a pre-commit rejection in the middle of an
 * unrelated plan, with no obvious cause and a tempting one-character "fix" to
 * the pattern.
 *
 * Case-sensitive, and anchored on the command's CONSTRUCTION rather than on the
 * word alone, for the reason `DAV_FETCH_CALL` gives one constant up. Three
 * modules already discuss this command in prose; `MAX_APPEND_LITERAL_BYTES` and
 * `DRAFT_APPEND_FLAGS` merely contain the same six letters; and the response
 * code the server sends back on success carries them as a prefix, so a pattern
 * keyed on the spelling alone would ban reading the answer to the very command
 * it protects -- the same trap `non-peeking-fetch-item` is anchored against. The
 * two alternatives are the only two ways a command line is built in this
 * codebase: after an interpolated tag, and at the head of a quoted string handed
 * to the generic sender.
 *
 * Collected from `src/` only. `test/append.test.ts` asserts the command line
 * byte for byte in order to prove the exchange is correct, and a fixture is not
 * a code path -- the ban is on a shipped construction site. That fixture happens
 * to spell a literal tag and so would not match even unscoped, but that is a
 * coincidence of spelling rather than a property, and the scope is what actually
 * holds.
 */
export const APPEND_COMMAND = /(?:\$\{[^}\n]*\}|["'`])\s*APPEND /;

/** The one file under `APPEND_SCOPE` permitted to match `APPEND_COMMAND`. */
export const APPEND_OWNER = "src/mail/service.ts";

/** The tree `APPEND_COMMAND` is collected from. See the docstring above for why
 *  this is not the full scanned surface. */
export const APPEND_SCOPE = "src/";

/**
 * The construction site of the mutating mailbox open, permitted exactly once in
 * the source tree.
 *
 * THE RULE. Exactly one place under `src/` builds the command that opens a
 * mailbox for changing, and it is inside `withMutatingMailboxOver` in
 * `src/mail/service.ts` (phase 20, D-03). Every read opens its mailbox
 * read-only. This one open is the only way any code path gets a mailbox the
 * server will let it change, and it sits behind its own orchestrator, its own
 * session type and its own access check.
 *
 * WHY A COUNT. Zero is a violation as two is. A second site is a second way to
 * reach a mailbox opened for changing, arriving without a decision; that is
 * the PITFALLS #32 failure, where every read call site ends up one argument
 * away from changing mail. Zero means the mutating path was deleted, renamed
 * or emptied. That direction is the quieter one: nothing fails on the way out,
 * because the tests that covered the deleted code leave with it.
 *
 * WHY THE OWNER FILE MAY HOLD ONLY ONE. The collector takes EVERY match with a
 * fresh global copy per file, as the confirm-line count's does, and the
 * checker allows the owner one entry. With `search()` a file contributes at
 * most one entry, so a second open inside `src/mail/service.ts` itself would
 * pass. It must not: "one site" is about sites, not files.
 *
 * WHAT IT DOES NOT SEE. Three shapes are outside this pattern's reach:
 *
 *   1. a command line carrying a literal tag rather than an interpolated one;
 *   2. the command word held in a variable and handed to the generic sender in
 *      `src/mail/imap-session.ts`;
 *   3. a lowercase command word. The wire is case-insensitive, so a lowercase
 *      open works on the server. The pattern stays case-sensitive anyway,
 *      because a case-insensitive one would fire on ordinary strings that begin
 *      with the English word "Select" followed by a space.
 *
 * COMMENTS. The collector matches against the file with its comment LINES
 * blanked (`withoutCommentLines`), so a commented-out open does not satisfy the
 * count. Without that, deleting the real open and leaving a comment that quotes
 * it would keep the count at one and the missing arm quiet, which is the exact
 * quiet loss that arm exists to catch. Only whole-line comments are blanked: a
 * line whose first non-space characters are `//`, and a block comment that
 * starts a line, up to its close. One shape is left, and it still counts: a
 * comment trailing code on the same line (`foo(); // was ...`). Telling that
 * `//` from one inside a string or a regex literal needs a real tokenizer, and
 * a tokenizer that misreads one would hide real code, which is worse than the
 * gap. A block comment opened after code on a line is not tracked either, so
 * its following lines count as code.
 *
 * The one legitimate site is held one layer up instead, by the byte-exact
 * assertion on the recorded open line in `test/triage.test.ts`, which reads
 * what was actually sent rather than the shape of the source that sent it. A
 * count believed to prove more than it does is worse than one whose limits are
 * written down.
 *
 * PROSE DISCIPLINE. The scope is the whole source tree and the walk runs on
 * every commit, so describe this command BY ROLE in `src/` -- "opened in the
 * mutating form", "the mutating open" -- and never by name followed by an
 * argument. A whole-line comment no longer counts here (see COMMENTS), but a
 * trailing one still does, and the write's count one constant up still reads
 * comments. Describing it by role keeps every one of those quiet.
 *
 * THE SHAPE. The same anchoring as `APPEND_COMMAND`: after an interpolated tag,
 * or at the head of a quoted string, case-sensitive, with a trailing space.
 * Those are the only two ways a command line is built in this codebase.
 * Measured before arming: this pattern matched nothing under `src/`, `test/`
 * or `scripts/`, so its missing arm would have fired the moment it existed
 * without a site. It was armed in the same commit as the site.
 *
 * Collected from `src/` only. Tests and fixtures spell the command on purpose,
 * to script the server's side and to assert the recorded line byte for byte,
 * and a fixture is not a code path.
 *
 * No `g` flag. The collector builds its own global copy per file, because a
 * shared global regex carries `lastIndex` from one file into the next.
 */
export const MUTATING_OPEN_COMMAND = /(?:\$\{[^}\n]*\}|["'`])\s*SELECT /;

/** The one file under `MUTATING_OPEN_SCOPE` permitted to match
 *  `MUTATING_OPEN_COMMAND`, and only once. */
export const MUTATING_OPEN_OWNER = "src/mail/service.ts";

/** The tree `MUTATING_OPEN_COMMAND` is collected from. Tests and fixtures spell
 *  the command on purpose. */
export const MUTATING_OPEN_SCOPE = "src/";

/**
 * The mutating-open construction sites one file contributes, as `scan()`
 * collects them.
 *
 * EVERY match, not the first, with a fresh global copy per call: two sites in
 * the owner file are two sites. Matched against the file with its comment
 * lines blanked, so a commented-out open is not a site; the positions are
 * unchanged by the blanking. See the `MUTATING_OPEN_COMMAND` docstring,
 * COMMENTS, for what is and is not blanked. An empty list for a file outside
 * `MUTATING_OPEN_SCOPE`.
 *
 * Exported so the tests can feed the checker a real source sample through the
 * collector `scan()` itself uses.
 *
 * @param {string} relativePath
 * @param {string} contents
 * @returns {Array<{file: string, line: number, column: number}>}
 */
export function collectMutatingOpens(relativePath, contents) {
  if (!relativePath.startsWith(MUTATING_OPEN_SCOPE)) return [];
  const code = withoutCommentLines(contents);
  return [...code.matchAll(new RegExp(MUTATING_OPEN_COMMAND, "g"))].map(
    (match) => ({ file: relativePath, ...positionOf(code, match.index) }),
  );
}

/**
 * An import of the mutating orchestrator, permitted in exactly one file of the
 * source tree.
 *
 * THE RULE. Exactly one file under `src/` imports `withMutatingMailbox` or
 * `withMutatingMailboxOver` from the service module: `src/mail/triage.ts`
 * (phase 20, D-05). That module exports narrow verbs and never a session.
 * Everything else that needs a message changed calls one of those verbs. The
 * service module defines the orchestrator and imports nothing from itself, so
 * it is not an importer and is not counted.
 *
 * WHY A COUNT. A second importer is a second place that can hold a mailbox
 * opened for changing and do whatever it likes in it, arriving without a
 * decision. A tool that imported the orchestrator directly would skip the
 * verbs, and the verbs are where "one message, one flag, no body fetch" lives.
 * Zero importers means the verbs module was deleted, renamed or rewired, and
 * nothing fails on the way out: the tests that covered it leave with it.
 *
 * WHAT IT DOES NOT SEE. Each of these reaches the orchestrator and fires
 * nothing:
 *
 *   1. a namespace import of the service module (`import * as s from ...`),
 *      followed by a call through it;
 *   2. a star re-export of the service module (`export * from ...`) in another
 *      module, with the orchestrator imported from there;
 *   3. a dynamic import of the service module (`await import(...)`);
 *   4. an alias: a module path alias that does not end in `/service`, or the
 *      orchestrator re-bound to another name inside the owner and handed on.
 *
 * A renamed binding in the braces (`withMutatingMailbox as open`) IS seen,
 * because the orchestrator's own name is still spelled inside them.
 *
 * COMMENTS. As for the mutating open: the collector matches against the file
 * with its comment LINES blanked, so an import that was deleted and left
 * quoted in a comment does not satisfy the count. A comment trailing code on
 * the same line still counts; see `MUTATING_OPEN_COMMAND`, COMMENTS, for why
 * that one is left.
 *
 * A named re-export (`export { withMutatingMailbox } from "./service"`) IS
 * seen too. It is the cheapest way round an import-only count: one barrel line
 * anywhere under `src/`, then an ordinary import from the barrel. The barrel
 * line is itself the second importer, so it is counted as one.
 *
 * THE SHAPE. An import or export statement that names either orchestrator
 * inside its braces, from a module path ending in `/service` with an optional
 * TypeScript or JavaScript extension. A type-only one matches too, and so does
 * one spread over several lines. It matched nothing under `src/`, `test/` or
 * `scripts/` before the owner existed, and it was armed in the same commit.
 * Widening it to the export form also matched nothing new under `src/`.
 *
 * Collected from `src/` only. Tests import the stream-pair form to drive it
 * through the in-memory duplex, and a test is not a code path.
 *
 * No `g` flag: `scan()` uses `String.prototype.search`, which takes the first
 * match only, so a file that imports it twice is one entry.
 */
export const MUTATING_SESSION_IMPORT =
  /(?:import|export)\s*(?:type\s*)?\{[^}]*\bwithMutatingMailbox(?:Over)?\b[^}]*\}\s*from\s*["'][^"'\n]*\/service(?:\.[cm]?[jt]s)?["']/;

/** The one file under `MUTATING_SESSION_SCOPE` permitted to match
 *  `MUTATING_SESSION_IMPORT`. */
export const MUTATING_SESSION_OWNER = "src/mail/triage.ts";

/** The tree `MUTATING_SESSION_IMPORT` is collected from. Tests drive the
 *  orchestrator directly, and a test is not a code path. */
export const MUTATING_SESSION_SCOPE = "src/";

/**
 * The importers of the mutating orchestrator one file contributes, as
 * `scan()` collects them.
 *
 * Exported so the tests can feed the checker a real source sample, through
 * the collector `scan()` itself uses, rather than a hand-made position. At most
 * one entry per file: the first match, as `String.prototype.search` finds it.
 * Matched against the file with its comment lines blanked, so a commented-out
 * import is not an importer. An empty list for a file outside
 * `MUTATING_SESSION_SCOPE`.
 *
 * @param {string} relativePath
 * @param {string} contents
 * @returns {Array<{file: string, line: number, column: number}>}
 */
export function collectMutatingSessionImports(relativePath, contents) {
  if (!relativePath.startsWith(MUTATING_SESSION_SCOPE)) return [];
  const code = withoutCommentLines(contents);
  const index = code.search(MUTATING_SESSION_IMPORT);
  if (index === -1) return [];
  return [{ file: relativePath, ...positionOf(code, index) }];
}

/**
 * A bare network call, permitted in exactly one module of the subscription-feed
 * tree.
 *
 * The same argument `DAV_FETCH_CALL` carries, restated for a fetch that is
 * deliberately NOT `davFetch`. A `CS:source` href names an arbitrary
 * third-party host the account does not control -- the debug session that
 * found this measured it live, `sm-cal.apple.com`, anonymously readable -- so
 * this fetch must NEVER carry the iCloud credential, which is exactly what
 * `davFetch` would attach unconditionally. A second module reaching the
 * network directly under this scope defeats that guarantee silently: the code
 * works, right up until it posts the user's Apple ID and app-specific
 * password to a stranger's server.
 *
 * A count rather than a negative, for the reason every other choke point in
 * this file gives: a choke point that was quietly moved, renamed, or emptied
 * guards nothing, and a silently-deleted one is easier to miss than a
 * duplicated one.
 *
 * Collected from `src/feed/` only, a scope disjoint from `DAV_FETCH_SCOPE` --
 * the two trees have nothing to say about each other, and a caller reaching
 * the network from `src/dav/` is `DAV_FETCH_CALL`'s violation, not this one's.
 *
 * The same regex as `DAV_FETCH_CALL`, but exported as its own constant rather
 * than reused: the two are collected over disjoint scopes, and a shared
 * pattern collected twice would double-report a single match if the scopes
 * ever overlapped.
 */
export const SUBSCRIPTION_FEED_FETCH_CALL = /\bfetch\s*\(/;

/** The one file under `SUBSCRIPTION_FEED_FETCH_SCOPE` permitted to match
 *  `SUBSCRIPTION_FEED_FETCH_CALL`. */
export const SUBSCRIPTION_FEED_FETCH_OWNER = "src/feed/subscription-feed.ts";

/** The tree `SUBSCRIPTION_FEED_FETCH_CALL` is collected from. */
export const SUBSCRIPTION_FEED_FETCH_SCOPE = "src/feed/";

/**
 * A read of the grant's props, permitted in exactly one file of the source
 * tree.
 *
 * THE RULE. Exactly one file under `src/` reads the grant's props, and that
 * file is the door in `src/mcp/api-handler.ts`. The door checks that the grant
 * is the owner's, answers every other grant with a 401 it builds itself, and
 * hands the tool layer a promise of the principal. Everything past the door
 * gets the principal by closure. Nothing past the door looks at the grant
 * again, so nothing past the door can serve a grant the door would refuse.
 *
 * WHY A COUNT RATHER THAN A NEGATIVE. Zero readers means the owner guard was
 * deleted or moved, and nothing fails on the way out: a handler that never
 * reads the grant serves every grant. "No second reader" is trivially true of
 * a tree with no reader at all. A second reader is the other failure: a read
 * added for convenience is a second place that decides who the caller is, and
 * the two drift. Zero is as much a violation as two.
 *
 * TWO ARMS. The first is the props member read off an identifier named `ctx`,
 * bounded as whole words, with the optional-chaining form and the non-null mark
 * included. The second is a call to the auth context reader,
 * `getMcpAuthContext`. Phase 9 D-08 says the factory never calls it, and spike
 * S1 showed it is the other way to reach the same props. The second arm goes
 * beyond D-22's wording. It only refuses more, and it had zero hits under `src/`
 * when it was added. To drop it, delete that one arm here and its two rows in
 * the test.
 *
 * THE MEMBER ACCESS MATCHES WHAT THE ACCOUNT-BINDING BAN MATCHES (code review
 * WR-03, and see `mail-secret-read` in the list above -- that one was a count
 * beside this one until phase 13 deleted the binding it counted the readers of,
 * and the shared member access outlived the count). The two were written in the
 * same phase and disagreed for no
 * reason: this one allowed white space around the dot and an optional question
 * mark, that one allowed neither. Both now allow white space, a new line, an
 * optional question mark and an optional non-null mark on either side of the
 * dot. THE MARK OWNS THE WHITE SPACE BEHIND IT, as one optional group, for the
 * reason the environment-write rule spells out at length further up this file:
 * split into two optional white-space runs, a space before the dot could be
 * taken by either, which is two ways to match every link and a cost that
 * doubles per link. Do not split that group into two optional pieces.
 *
 * The non-null mark is the one that mattered here: a context parameter
 * typed as possibly absent is written that way by the compiler's own prompting,
 * and there is no compiler backstop on this count, so a second reader spelled
 * that way was invisible. Keep the two member accesses identical. A difference
 * between them is a difference nobody decided.
 *
 * WHAT IT DOES NOT SEE. Each of these reads the props and fires nothing:
 *
 *   1. props destructured from the context (`const { props } = ctx`);
 *   2. the context under another name (`context.props`, `executionCtx.props`);
 *   3. a props read hidden behind a helper that lives in the owner file and is
 *      called from elsewhere;
 *   4. a type cast in parentheses around the context, which puts the cast
 *      keyword between the name and the dot.
 *
 * A computed member (`ctx["props"]`) is a fifth. A count believed to prove
 * more than it does is worse than one whose limits are written down.
 *
 * NEVER MATCH THE BARE WORD. The DAV library uses `props` all over `src/dav/`
 * for PROPFIND results (`response.props`, `props.displayname`). A rule that
 * fires there would be narrowed by the next person in a hurry, and a narrowed
 * rule is how this guard would quietly leave.
 *
 * THIS COUNT IS NOT THE PROPS CONSTRUCTOR'S COUNT, AND THE TWO ARE DIFFERENT
 * QUESTIONS (Phase 9 D-22, settled by Phase 11). This one counts files that
 * READ the grant's props off the execution context. `PRINCIPAL_CONSTRUCTOR`
 * below counts sites that MINT a principal from a props object. A reader can
 * hand the props anywhere; a minter can be handed props from anywhere. Neither
 * question answers the other, which is why the constructor got a count of its
 * own rather than an arm on this one.
 *
 * The note that used to sit here asked Phase 11 for that arm, on the ground
 * that nothing called the constructor yet and a count of its callers would fail
 * on zero. All three claims stopped being true when Phase 11 landed. The
 * constructor now has exactly TWO callers — `src/mcp/api-handler.ts`, which
 * builds a principal from a stored grant, and `src/auth/login-handler.ts`,
 * which builds one from values a person just typed — so an arm on a one-owner
 * rule was the wrong shape as well as the wrong place. See
 * `PRINCIPAL_CONSTRUCTOR` for the argument that there are legitimately two.
 *
 * Comments count. In every file under `src/` except the owner, write "the
 * grant's props" and never the spelled read. No `g` flag: `scan()` uses
 * `String.prototype.search`, which takes the first match only.
 */
export const PROPS_READER =
  /\bctx\s*(?:[?!]\s*)?\.\s*props\b|\bgetMcpAuthContext\s*\(/;

/** The one file under `PROPS_READER_SCOPE` permitted to match `PROPS_READER`. */
export const PROPS_READER_OWNER = "src/mcp/api-handler.ts";

/** The tree `PROPS_READER` is collected from. Tests build props on a real
 *  execution context and must spell the read, and a test is not a code path. */
export const PROPS_READER_SCOPE = "src/";

/**
 * An import of the one password reader, permitted in exactly two files of the
 * source tree.
 *
 * THE RULE. Exactly two files under `src/` import `passwordOf` from the
 * principal module: `src/mail/credentials.ts` and `src/dav/transport.ts`. The
 * principal module defines the reader and imports nothing, so it is not an
 * importer and is not counted. Everything else that needs to act for a
 * principal hands the principal to one of those two files and never sees the
 * password.
 *
 * WHY A COUNT RATHER THAN A NEGATIVE. One owner gone means a login path was
 * deleted, moved, or rewritten to get the password some other way, and nothing
 * fails on the way out: the tests that covered the deleted code leave with it.
 * "No third importer" is trivially true of a tree with no importer at all. A
 * third importer is the other failure: a second thing in this project that can
 * read a password, arriving without a decision. Zero, one and three are all
 * violations. Only two passes, and only these two.
 *
 * WHY THERE ARE TWO OWNERS. Every count above has one owner. This one has two
 * because the password is spent in two places that cannot share code. One
 * writes the mail login onto the socket. The other builds the DAV
 * authorization header. `src/mail` and `src/dav` may not import each other, so
 * neither can borrow the other's reader. The missing arm therefore fires once
 * PER absent owner and names that owner, not once when the list is empty.
 *
 * WHAT IT DOES NOT SEE. Each of these reaches the reader and fires nothing:
 *
 *   1. a namespace import of the principal module (`import * as p from ...`),
 *      followed by `p.passwordOf(...)`;
 *   2. a re-export of the reader through another module, imported from there;
 *   3. a dynamic import of the principal module (`await import(...)`);
 *   4. an alias: a module path alias that does not end in `/principal`, or the
 *      reader re-bound to another name inside an owner file and handed on.
 *
 * A renamed binding in the braces (`passwordOf as read`) IS seen, because the
 * reader's own name is still spelled inside them. A count believed to prove
 * more than it does is worse than one whose limits are written down.
 *
 * THE SHAPE. An import statement that names the reader inside its braces, from
 * a module path ending in `/principal` with an optional TypeScript or
 * JavaScript extension. A type-only import matches too, and so does an import
 * spread over several lines, because the brace span is "anything but a closing
 * brace". It matched nothing under `src/` at the Phase 9 base. It was armed
 * only after both chains landed (Phase 9 D-25): armed after one, the hook would
 * have refused every commit of the other.
 *
 * No `g` flag: `scan()` uses `String.prototype.search`, which takes the first
 * match only, so a file that imports the reader twice is one entry.
 */
export const PASSWORD_READER_IMPORT =
  /import\s*(?:type\s*)?\{[^}]*\bpasswordOf\b[^}]*\}\s*from\s*["'][^"'\n]*\/principal(?:\.[cm]?[jt]s)?["']/;

/** The two files under `PASSWORD_READER_SCOPE` permitted to match
 *  `PASSWORD_READER_IMPORT`. The mail login first, then the DAV header. */
export const PASSWORD_READER_OWNERS = Object.freeze([
  "src/mail/credentials.ts",
  "src/dav/transport.ts",
]);

/** The tree `PASSWORD_READER_IMPORT` is collected from. Tests build principals
 *  and may read one back, and a test is not a login path. */
export const PASSWORD_READER_SCOPE = "src/";

/**
 * The one function that turns an address into a user id, permitted in exactly
 * one file of the source tree.
 *
 * THE RULE. Exactly one file under `src/` hashes an address into the id every
 * store key is scoped by, and it is `src/principal.ts`. ISO-05 rule 10 states
 * it in prose -- "no second function that turns an address into a user id may
 * exist anywhere" -- and D-18 makes it mechanical. Everything that needs the id
 * reads it off the signed-in principal; nothing computes one for itself.
 *
 * WHY A COUNT RATHER THAN A NEGATIVE. Two producers is the loud failure: they
 * drift, and the day they disagree one person becomes two users or two people
 * become one. A user whose id changed loses every staged attachment and every
 * pending confirmation in a single deploy; two users who collapsed onto one id
 * read each other's. Zero producers is the quiet failure, and it is the one a
 * negative cannot see at all: "no second hashing site" is trivially true of a
 * tree with no hashing site left. A choke-point that was deleted, renamed, or
 * rewritten into a form this count cannot see guards nothing, and nothing goes
 * red on the way out, because the tests that covered it leave with it.
 *
 * WHY THE ANCHOR NAMES THE ENCODER, AND WHY A BARE DIGEST COUNT DOES NOT WORK.
 * There are three Web Crypto digest call sites under `src/` and two of them are
 * legitimate non-owners: `src/confirm.ts` hashes a canonical change and two
 * change hashes through `TOKEN_ENCODER`, and `src/auth/login-handler.ts` hashes
 * the login gate's own submitted secret through a function-local lower-case
 * encoder. None of them hashes an address. A bare digest count would report
 * three owners and -- because the pre-commit hook runs this scanner under
 * `set -e` -- would refuse every commit in the repository, including commits on
 * unrelated work. So the anchor is the digest call TOGETHER WITH the module
 * scope encoder's name, and two properties of it are load-bearing rather than
 * cosmetic:
 *
 *   1. THE WORD BOUNDARY IS MANDATORY. The encoder's name is a SUBSTRING of
 *      the confirm module's. Without a boundary on both sides the anchor
 *      matches there too and the count reports a second owner.
 *   2. THERE IS NO CASE-INSENSITIVE FLAG. The login gate's encoder differs
 *      only in letter case, and a case-insensitive anchor reaches it.
 *
 * Both were measured in both directions before this count was armed. Every
 * unsafe variant reports at least one owner too many, and every one of them
 * freezes the repository. The test block carries a must-not-match row for each
 * of the five non-owner digest lines, so a broken anchor fails there first.
 *
 * WHY THE LOGIN GATE'S SECRET AND THE CHANGE HASHES ARE NOT FOLDED IN. Phase 9
 * D-28 set the precedent when it left the login gate's own secret out of the
 * mail-secret count: one count answering two different questions answers
 * neither well. This count answers "how many things produce a user id", and
 * neither a submitted secret nor a canonical change is an address.
 *
 * WHAT IT DOES NOT SEE. Each of these turns an address into an id and fires
 * nothing:
 *
 *   1. the encoder renamed -- `const E = new TextEncoder()` and then
 *      `E.encode(address)`. That is the price of anchoring on a name, and it
 *      is written down here rather than hidden. The tell is the gap between
 *      the digest population and the anchored count;
 *   2. an encoder constructed inline at the digest call, with no module-scope
 *      constant at all;
 *   3. an address hashed by a library rather than by Web Crypto;
 *   4. a digest call whose arguments are spread over more than 200 characters
 *      between the opening parenthesis and the encoder name. The bound is what
 *      keeps the match linear; it is not a licence to reformat past it;
 *   5. WHAT the site hashes. This sees an encoder name, not an address. The
 *      owner could start hashing something else entirely and the count would
 *      still say one. `test/key-shapes.test.ts` is what holds the OUTPUT to
 *      the spec; this holds the number of producers.
 *
 * A count believed to prove more than it does is worse than one whose limits
 * are written down.
 *
 * THE SHAPE. A Web Crypto digest call, then at most 200 characters that do not
 * cross a closing parenthesis, then the encoder's name as a whole word. The
 * character class matches newlines, so a call formatted across several lines is
 * still one match; it cannot cross a `)`, so the anchor cannot reach past the
 * end of the call's argument list. No `g` flag: `scan()` uses
 * `String.prototype.search`, which takes the first match only.
 */
export const ADDRESS_HASH =
  /crypto\.subtle\.digest\s*\(\s*[^)]{0,200}\bENCODER\b/;

/** The one file under `ADDRESS_HASH_SCOPE` permitted to match `ADDRESS_HASH`. */
export const ADDRESS_HASH_OWNER = "src/principal.ts";

/** The tree `ADDRESS_HASH` is collected from. Tests compute expected ids to
 *  compare against, and a test is not a producer. */
export const ADDRESS_HASH_SCOPE = "src/";

/**
 * A call to the props-backed principal constructor, permitted in exactly two
 * files of the source tree.
 *
 * THE RULE. Exactly two files under `src/` turn a props object into a
 * principal: `src/mcp/api-handler.ts` and `src/auth/login-handler.ts`. The
 * principal module DEFINES the constructor and is not a caller, so it is not
 * counted. Everything else that needs to act for somebody is handed the
 * principal the door already built and never mints one.
 *
 * WHY A COUNT RATHER THAN A NEGATIVE. A third minting site is a third place in
 * this project that can turn a props object into a live session, arriving
 * without a decision — and the props it is handed need not be the props the
 * door checked. Zero is the other failure and the quieter one: one caller gone
 * means an identity path was deleted, moved, or rewritten to get identity some
 * other way, and nothing fails on the way out, because the tests that covered
 * the deleted code leave with it. "No third caller" is trivially true of a tree
 * with no caller at all. Zero, one, and three are all violations. Only two
 * passes, and only these two.
 *
 * WHY THERE ARE TWO OWNERS. The count above this one has a single owner. This
 * one has two because the two callers build from two different SOURCES and
 * neither can borrow the other's:
 *
 *   1. The door builds from a STORED grant's props, which the OAuth provider
 *      decrypted and put on the execution context. That is the serving path.
 *   2. The login handler builds from values the person JUST TYPED, before any
 *      grant exists, because that is the only way to hand a principal to the
 *      session runner and prove the credentials at Apple. It cannot take one
 *      from the door — there is no grant yet — and it cannot hand a look-alike
 *      to the password reader either: that reader answers only the very object
 *      this constructor built, so a hand-made stand-in reaches nothing.
 *
 * The missing arm therefore fires once PER absent owner and names that owner,
 * not once when the list is empty. This is the same shape as the password
 * count, for the same reason, and NOT the shape of the one-owner counts.
 *
 * WHY IT IS NOT AN ARM ON `PROPS_READER`. That count's own note used to ask for
 * one. The two ask different questions — that one counts files that READ the
 * props off the context, this one counts sites that MINT a principal from a
 * props object — and folding them together would make one count answer both
 * and neither well. Phase 9 D-28 set that precedent when it left the login
 * gate's secret out of the mail-secret count.
 *
 * WHAT IT DOES SEE that a reader might not expect: a call through a namespace
 * import. The word boundary sits on the constructor's own name, and a member
 * access puts a dot in front of it rather than a word character, so a namespace
 * call is matched and counted like any other. That only refuses more.
 *
 * WHAT IT DOES NOT SEE. Each of these mints a principal and fires nothing:
 *
 *   1. the constructor RE-BOUND to another name and called through it, whether
 *      by a renamed import, by an assignment to a local, or by a parameter it
 *      is passed as. The name is the whole anchor, and this is the price of
 *      anchoring on a name — written down here rather than hidden;
 *   2. a re-export of the constructor through another module, imported from
 *      there under a different name;
 *   3. a dynamic import of the principal module, then a call off the resolved
 *      namespace under a different name;
 *   4. a computed call: the name reached as a string through square brackets,
 *      or through a table of constructors keyed by anything at all;
 *   5. a call with a COMMENT between the name and its opening parenthesis.
 *      White space of any kind, a line break included, IS matched — only a
 *      comment breaks the run.
 *
 * Two more shapes are worth naming because they are the tempting ones rather
 * than the exotic ones: a WRAPPER inside one of the two owner files, exported
 * and called from a third file — the call this count sees still lives in an
 * owner, so the count still reads two — and a principal built by hand as an
 * object literal, which this cannot see at all and which the password reader
 * refuses at run time instead. A count believed to prove more than it does is
 * worse than one whose limits are written down.
 *
 * THE SHAPE. The constructor's name as a whole word followed by an opening
 * parenthesis, NOT preceded by the declaration keyword — that keyword in front
 * is what tells a definition from a call, and it is why the principal module's
 * own definition is not counted as a caller there. The lookbehind is bounded at
 * eight white-space characters so a definition split across lines by the
 * formatter is still recognised as one; it is bounded rather than open for the
 * same reason every other bound in this file is. A plain named import is not
 * matched, because an import does not put a parenthesis after the name. No `g`
 * flag: `scan()` uses `String.prototype.search`, which takes the first match
 * only, so a file that calls the constructor twice is one entry.
 *
 * Comments count. In every file under `src/`, describe the construction in
 * plain words unless you mean the call — a comment that spells the name with a
 * parenthesis after it in a third file fails the commit hook in the middle of
 * unrelated work. Naming it with no parenthesis, as both owners and the door's
 * prose already do, is always safe.
 */
export const PRINCIPAL_CONSTRUCTOR =
  /(?<!\bfunction\s{1,8})\bprincipalFromProps\s*\(/;

/** The two files under `PRINCIPAL_CONSTRUCTOR_SCOPE` permitted to match
 *  `PRINCIPAL_CONSTRUCTOR`. The door first, then the login page. */
export const PRINCIPAL_CONSTRUCTOR_OWNERS = Object.freeze([
  "src/mcp/api-handler.ts",
  "src/auth/login-handler.ts",
]);

/** The tree `PRINCIPAL_CONSTRUCTOR` is collected from. Tests build principals
 *  from hand-made props all over `test/`, and a test is not an identity path. */
export const PRINCIPAL_CONSTRUCTOR_SCOPE = "src/";

/**
 * The definition of the one function that composes the human-facing line.
 *
 * THE RULE. One composer, at one definition site, so five call sites cannot
 * phrase five sentences that drift apart. The sentence a user reads before they
 * agree to a destructive change is the one thing the confirmation token cannot
 * bind -- it is written from the preview payload, by a model that is reading
 * stranger-authored content in the same context window -- so CONF-04 moves the
 * writing of it into this server. Two composers is two registers, and the drift
 * between them is invisible until somebody reads two transcripts side by side.
 *
 * WHY A COUNT RATHER THAN A SCOPED NEGATIVE. The standing answer every count in
 * this file gives. The natural spelling would be "ban a composer outside the
 * confirm module", and this scanner has no per-rule path exemption: `EXCLUDED`
 * skips a file for EVERY rule. Buying that exemption by path would silently drop
 * the logging ban and the account-binding ban on the one module that holds the
 * confirmation gate.
 *
 * WHAT THE COUNT SEES THAT A NEGATIVE CANNOT. Zero is a violation. A composer
 * that was deleted, renamed or inlined back into its call sites guards nothing,
 * and that direction is far easier to miss, because nothing fails on the way
 * out: the tests covering the deleted code are deleted with it. Five phases --
 * contacts, collections, RSVP, mail triage, draft editing -- inherit this
 * sentence rather than re-deciding it, and each of them is a session that could
 * lose it without a single assertion going red.
 *
 * WHAT IT DOES NOT AND CANNOT SEE. Five shapes get past this rule, and naming
 * them is what stops a later reader believing it proves more than it does. The
 * first four each produce a second human-facing sentence and fire nothing:
 *
 *   1. a second composer bound to a `const` ARROW rather than declared. No
 *      declaration keyword follows, so nothing matches -- and this is the one
 *      most likely to arrive by accident, because it is a style choice rather
 *      than an evasion;
 *   2. a line assembled INLINE at a tool shaper as a template literal, which is
 *      the shortest route and therefore the tempting one;
 *   3. a RE-EXPORT under an alias, imported from there under a different name;
 *   4. a helper that takes the composed line and REWRITES it before it reaches
 *      the response -- the count sees one composer and the user reads something
 *      else.
 *
 * The fifth runs the other way and is the sharper one, because it defeats the
 * arm this rule exists for rather than the arm it shares with a plain ban:
 *
 *   5. a COMMENT satisfies the presence arm. This pattern matches text, not
 *      code, so any line under `src/confirm.ts` that names the composer with the
 *      declaration keyword in front of it -- in prose, in a docstring, in a
 *      commented-out draft -- makes the collected list non-empty. Delete, rename
 *      or inline the real definition after that and `composers.length === 0` is
 *      false, `confirm-line-composer-missing` never fires, and the scan passes
 *      with no composer in the tree -- which is precisely the failure direction
 *      the paragraph above says this count exists to catch. No such comment
 *      exists today. Do not rely on the zero arm alone, and do not write that
 *      comment: name the composer WITHOUT the keyword in front of it, exactly as
 *      the `does not see a CALL or an IMPORT` samples do -- which is also why
 *      this bullet describes the shape instead of quoting it.
 *
 * A SIXTH SHAPE USED TO GET PAST AND NO LONGER DOES. Two definitions in the
 * OWNER file both passed, because the collector used `String.prototype.search`
 * and a file could contribute at most one entry: two composers in
 * `src/confirm.ts` produced one entry, that entry was the owner, and the checker
 * skipped it. "One composer, at one definition site" was then false with the
 * scan green. The collector now counts EVERY match in a file and the checker
 * reports the second and later occurrences in the owner, so the count is a count
 * in both files and within one.
 *
 * What actually holds those four is named here rather than left implied: the
 * byte-exact line table in `test/confirm.test.ts`, which pins every sentence the
 * composer can produce and would fail the moment a second register appeared in a
 * response; and the fence audit's key-set comparison in
 * `test/dav-fence-audit.test.ts`, which pins the exhaustive key set of both
 * halves of both write shapes, so a second line field has nowhere quiet to land.
 *
 * THE SHAPE. The declaration keyword, whitespace, then the composer's name.
 * Anchoring on the KEYWORD is what makes a call site and an import invisible,
 * and that is load-bearing rather than tidy: every call site lives under the
 * collected scope, so a pattern keyed on the bare name would report the very
 * sites this rule exists to protect and the pre-commit hook would refuse every
 * commit in the repository. White space of any kind is matched, a line break
 * included, so a signature the formatter broke up is still one definition.
 *
 * No `g` flag on the exported constant, and one test asserts the absence. The
 * collector needs every match rather than the first, so it builds its own global
 * copy per file with `new RegExp(CONFIRM_LINE_COMPOSER, "g")`. That is the right
 * way round: a shared global regex carries `lastIndex` between files, so a rule
 * exported with the flag on would silently start matching from wherever the
 * previous file left off.
 */
export const CONFIRM_LINE_COMPOSER = /\bfunction\s+composeConfirmationLine\b/;

/** The one file under `CONFIRM_LINE_SCOPE` permitted to match
 *  `CONFIRM_LINE_COMPOSER`. */
export const CONFIRM_LINE_OWNER = "src/confirm.ts";

/** The tree `CONFIRM_LINE_COMPOSER` is collected from. A test that declares a
 *  look-alike to prove the pattern is not vacuous is not a shipped composer. */
export const CONFIRM_LINE_SCOPE = "src/";

/**
 * The DAV write modules, and a recorded disposition for every name each of them
 * exports.
 *
 * THE RULE. Three modules under `src/dav/` are declared here because each of
 * them exports, or is about to export, a network-reaching entry point the tool
 * layer can reach. Every name those modules export today carries a disposition:
 * either the exact string `"guarded"`, meaning the name must appear in the
 * `dav-concurrent-request` alternation, or a short prose reason saying why it
 * must not -- which is always the same kind of reason, that the function issues
 * no request at all. A new export in a declared module fails the scan until
 * somebody writes one of those two things down. That is the whole point: "write"
 * is not inferable from a name, so nothing will decide it automatically, and
 * v3.0 adds contact create and update, collection create, rename and delete,
 * event alarms and an invitation reply -- many new entry points, added by hand,
 * across several phases, by several sessions. The probability that every one of
 * them reaches the alternation unprompted is not high.
 *
 * WHY A COUNT RATHER THAN A SCOPED NEGATIVE. The same standing answer every
 * count in this file gives. The natural spelling would be "ban an unguarded
 * export under `src/dav/`, except in the modules that legitimately have one",
 * and this scanner has no per-rule path exemption: `EXCLUDED` skips a file for
 * EVERY rule. Buying that exemption by path would silently drop the logging
 * ban, the eager-load ban, the host-literal count and the fan-out rule itself on
 * the three modules that most need them, since they are the modules holding the
 * account's write path.
 *
 * WHAT THE COUNT SEES THAT A NEGATIVE CANNOT. A manifest that stopped matching
 * anything is a manifest that guards nothing. A declared module that was moved,
 * renamed, or emptied is never walked, its collected export list is empty, and
 * every name here comes back stale -- which is exactly right, and it is the
 * direction that is easier to miss, because nothing fails on the way out: the
 * tests that covered the deleted code are deleted with it. Zero is as much a
 * violation as an unmanifested extra.
 *
 * WHAT IT DOES NOT AND CANNOT SEE. `exportedFunctionNames` is a regex over
 * source text rather than a parser -- the file header forbids a dependency
 * outright, because the pre-commit hook runs before anything guarantees
 * `node_modules` is installed -- so four shapes are outside its reach:
 *
 *   1. a RE-EXPORT (`export { getEvent } from "./elsewhere";`). No `function`
 *      keyword follows the `export`, so nothing matches;
 *   2. a `const` ARROW export (`export const getEvent = async () => {};`). Same
 *      reason, and this is the one most likely to arrive by accident, because it
 *      is a style choice rather than an evasion;
 *   3. a name BOUND AND EXPORTED SEPARATELY (`function getEvent() {}` on one
 *      line, `export { getEvent };` on another). The `export` and the `function`
 *      are never adjacent;
 *   4. a MODULE-LOCAL function that is nonetheless a fan-out entry point. Named
 *      concretely rather than left abstract: `pagedEvents` and `collectFrom` in
 *      `src/dav/calendar.ts` are both on the alternation and both invisible
 *      here, because neither is exported. The alternation covers them; this
 *      manifest cannot, and an export list is not a call-site list.
 *
 * What makes the regex SUFFICIENT rather than merely convenient is a narrower
 * fact about the tree as it stands: every export of all three declared modules
 * that is a FUNCTION is a plain `function` declaration. VALUE exports do exist
 * -- `MAX_RANGE_DAYS`, `MAX_SLOT_RANGE_DAYS`, `SLOT_GRANULARITY_MINUTES` and
 * `UNOBSERVED_DELIVERY` in `src/dav/calendar.ts`, `CONTACT_TERM_MAX_LENGTH` in
 * `src/dav/contacts.ts` -- and the reader does not see any of them, which is
 * correct, because a number is not an entry point and a manifest entry for one
 * would be a disposition nobody can act on. A function bound to a `const` arrow
 * would be invisible in exactly the same way and would NOT be correct, which is
 * gap 2 above.
 *
 * This paragraph claimed the wider fact -- that every export of the declared
 * modules is a plain `function` declaration -- and that was false the day it was
 * written, by five exports. A reader sent to verify it finds it false in thirty
 * seconds, and both conclusions available from that are wrong: either "the
 * manifest is broken and missing five entries", or "const exports must be
 * covered somehow, since this says there are none". A rule believed to prove
 * more than it does is worse than one whose limits are written down -- and the
 * sentence stating the limit is the last place that can afford to be wrong.
 *
 * TWO ABSENCES, RECORDED AS DECISIONS RATHER THAN LEFT TO BE RE-DERIVED.
 * `src/dav/discovery.ts` and `src/dav/transport.ts` both export names that ARE
 * in the `dav-concurrent-request` alternation -- `resolveDavAccount` and
 * `withRediscovery` in the first, and the transport the second builds -- and
 * neither is declared here. Neither exports a write entry point: their
 * alternation names arrived as READ-path round trips, costed for the request
 * budget rather than for anything they change on the account. Declaring either
 * is a decision a later phase can take, and finding this paragraph is what tells
 * that phase it is a decision rather than a gap.
 *
 * The module list is a JUDGEMENT and not a derivation. If a later phase adds a
 * write entry point to a module on neither list, this constraint does not see
 * it.
 */
export const DAV_WRITE_MODULES = Object.freeze({
  "src/dav/calendar.ts": {
    why: "The only module in the DAV tree that exports CalDAV write entry points, and since phase 17 (CALM-04) that includes the COLLECTION create as well as the object ones: createCalendarCollection issues a hand-rolled RFC 5689 extended MKCOL against a URL built from the account's own resolved home set. This sentence read 'the module a later phase's collection create, rename and delete WILL be added to' until that phase arrived, and a why written in the future tense about work that has landed is the same defect as a docstring describing old routing -- nothing fails when the prose stops matching the code. The rename and the delete are still ahead, in plans 17-04 and 17-06, and they belong in THIS module beside the create rather than in a sibling: a sibling would be a module on neither list, and a write entry point in a module this manifest does not name is invisible to it.",
    exports: {
      listCalendars: "guarded",
      calendarColorForWire:
        "A string transformation over an ALREADY-VALIDATED #RRGGBB colour. It appends the opaque alpha pair the wire wants and returns the eight-digit form; it takes no transport, validates nothing, and issues no request. The anchored pattern that refuses a malformed colour lives at the tool boundary, deliberately, so this is not a second mitigation drifting from the first.",
      createCalendarCollection: "guarded",
      updateCalendarCollection: "guarded",
      readCollectionState: "guarded",
      calendarChangesSince: "guarded",
      readSyncAnswer:
        "A reduction over responses the caller already holds; issues no request.",
      deleteCalendarCollection: "guarded",
      assertCtag:
        "An assertion over a binding the caller already holds. Throws or returns; no request. The neighbouring register assertEtag's entry uses, and for the same class of value: a revision read off a resource, refused when it is absent so a conditional operation cannot silently become an unconditional one.",
      observedOutcomes:
        "A comparison between values the CALLER ALREADY HOLDS. It is handed the change a property update asked for plus the collection state a fresh read already returned, and answers which properties that read found in place; it takes no transport, addresses no URL and issues no request. Issuing none is close to the REQUIREMENT rather than incidental: the whole correction in plan 17-10 is that the verdict comes from a read the ENTRY POINT performed and never from the update's own answer, so a version of this function that fetched anything would be free to fetch the wrong thing. It replaced propstatOutcomes, which was a reader over the property update's own multi-status -- retired in 17-10 because iCloud's answer carries no parsed property keys at all, measured live, which made that reader report a connection fault on every successful write. It is exported because the property it enforces -- a value the fresh read did not find is a REFUSAL rather than an implicit success, and a read that did not answer at all is neither -- is worth driving directly rather than only through the entry point above.",
      listEvents: "guarded",
      nextCivilDate:
        "A civil-date calculation over a date string. Takes no transport and issues no request.",
      findFreeSlots: "guarded",
      findWindowConflicts: "guarded",
      occurrenceWindowsOf:
        "An expansion of already-fetched resource text into time windows. Returns windows; no request.",
      busyIntervalOf:
        "A computation over an occurrence's times the caller already holds. Places it on the timeline, as an instant pair or a whole named day in a zone this server holds; takes no transport and issues no request.",
      getEvent: "guarded",
      uidFromObjectUrl:
        "A URL decomposition that reads a uid out of an object path. Parses a string and returns.",
      getEventWithEtag: "guarded",
      assertEtag:
        "An assertion over a header value the caller already holds. Throws or returns; no request.",
      updateOccurrenceBody:
        "A body builder over already-fetched resource text. Returns the text or null; no request.",
      patchEventBody:
        "A body builder over already-fetched resource text. Returns the text or null; no request.",
      planScopedDelete:
        "A plan computation over already-fetched resource text. Decides what a delete would do, and does none of it.",
      pinnedOccurrencesFor:
        "A computation over already-fetched resource text. Counts occurrences; issues no request.",
      updateEvent: "guarded",
      deleteEvent: "guarded",
      deliveryReportOf:
        "A reduction over participants the caller already holds. Returns a report; issues no request.",
      resolveOrganizerAddress: "guarded",
      resolveCalendarUserAddresses: "guarded",
      organizerAddressFrom:
        "A selection over an address list the caller already holds. Returns one address or throws; no request.",
      replyBody:
        "A body builder over already-fetched resource text. Returns the text or a refusal arm; no request.",
      planCreateTarget:
        "A plan computation that mints a uid and an object URL synchronously. Issues no request.",
      createEvent: "guarded",
      matchesKeyword:
        "A matcher over an occurrence the caller already holds. Returns a boolean; no request.",
      matchesAttendee:
        "A matcher over an occurrence the caller already holds. Returns a boolean; no request.",
      searchEvents: "guarded",
    },
  },
  "src/dav/contacts.ts": {
    why: "Read and write. It was declared here while still read-only, precisely because a later phase would add contact create to it -- declaring a module before its first write arrives is the point of this manifest, and phase 16 (CONW-01) is that phase arriving. Both writes are one card per request and both assert both of their URLs under the resolved CardDAV home set before anything reaches the wire: the create is conditional on the resource NOT existing, and the overwrite (CONW-02) is conditional on the version stamp the read returned, which is refused before the request when it is falsy because the library would otherwise drop it and make the overwrite unconditional.",
    exports: {
      listAddressBooks: "guarded",
      contactFilter:
        "A filter builder. Assembles the report body a query will carry, and does not issue the query.",
      matchesContact:
        "A matcher over a parsed contact the caller already holds. Returns a boolean; no request.",
      searchContacts: "guarded",
      getContact: "guarded",
      planContactCreateTarget:
        "A plan computation that mints a uid and an object URL synchronously. Issues no request, and asserts no containment because nothing is requested.",
      contactUidFromObjectUrl:
        "A reader over a URL the caller already holds. Reverses the object-name convention and returns the uid or null; no request.",
      createContact: "guarded",
      duplicateFilter:
        "A filter builder over ONE named property. Assembles the report body a query will carry, and does not issue the query.",
      findDuplicateCandidates: "guarded",
      getContactWithEtag: "guarded",
      updateContact: "guarded",
    },
  },
  "src/dav/diagnose.ts": {
    why: "Exports the collection write probe an earlier phase added, which creates, renames, recolours and deletes a real collection on a real account.",
    exports: {
      runDavDiagnosticOutcome: "guarded",
      runCollectionWriteProbe: "guarded",
      runTaskCollectionProbe: "guarded",
      runPropertyNameProbe: "guarded",
    },
  },
});

/**
 * Every name a module exports as a `function` declaration, in source order.
 *
 * A regex over source text rather than a parser, for the reason the file header
 * gives: no dependency may be added here, because the pre-commit hook runs
 * before anything guarantees `node_modules` is installed. See the
 * `DAV_WRITE_MODULES` docstring above for the four shapes this deliberately
 * cannot see.
 *
 * The pattern is constructed FRESH on every call rather than held at module
 * scope. The other constraint patterns in this file carry no global flag
 * because `scan()` reaches them through `String.prototype.search`, which ignores
 * `lastIndex`; this reader needs `matchAll`, which does not have that property,
 * so a shared module-level regex would carry `lastIndex` from one file into the
 * next and start skipping names depending on the order files happened to be
 * read.
 *
 * @param {string} contents
 * @returns {string[]}
 */
export function exportedFunctionNames(contents) {
  const declaration = /^export\s+(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)/gm;
  const names = [];
  for (const match of contents.matchAll(declaration)) names.push(match[1]);
  return names;
}

/**
 * Every violation id a count constraint can emit, both directions of each.
 *
 * Named here rather than left implicit so the test can assert set equality
 * against ids it produced by RUNNING the checkers -- the same guard the rule-id
 * assertion gives the pattern list. A constraint whose "missing" arm can never
 * fire looks exactly like a constraint that was never added.
 *
 * It is also the carve-out the per-root superset test reads. A count is a
 * whole-surface property: scanning one root in isolation reports the owners
 * living in the other roots as missing, which is correct for that narrower
 * question and wrong for the superset one.
 */
export const OWNERSHIP_VIOLATION_IDS = [
  "socket-choke-point-duplicated",
  "socket-choke-point-missing",
  "dav-host-outside-discovery",
  "dav-host-resolution-missing",
  "dav-fetch-outside-transport",
  "dav-fetch-choke-point-missing",
  "append-outside-drafts",
  "append-choke-point-missing",
  "subscription-feed-fetch-outside-owner",
  "subscription-feed-fetch-choke-point-missing",
  "props-reader-outside-owner",
  "props-reader-missing",
  "password-reader-outside-owners",
  "password-reader-missing",
  "address-hashing-site-outside-owner",
  "address-hashing-site-missing",
  "principal-constructor-outside-owners",
  "principal-constructor-missing",
  "dav-write-export-unmanifested",
  "dav-write-manifest-stale",
  "dav-write-entry-point-unguarded",
  "confirm-line-composer-duplicated",
  "confirm-line-composer-missing",
  "mutating-open-duplicated",
  "mutating-open-missing",
  "mutating-session-importer-outside-triage",
  "mutating-session-importer-missing",
];

// NOT ENFORCED HERE, and deliberately so rather than by oversight: the ban on
// ever creating a Worker binding named for the DAV library's logging switch.
// That name would live in `wrangler.jsonc` at the repository root, and
// `SCAN_ROOTS` below is the three source directories -- widening it to the root
// would walk every planning artifact on every commit and fire rules on
// documents describing the ban. It is recorded preventively instead, as a
// comment beside the binding, by plan 03-01.

/**
 * Paths the scanner skips.
 *
 * Exclusion is by PATH, never by cleverness in the regexes. Building patterns
 * from concatenated fragments to dodge self-matching is the kind of trick that
 * reads as an accident and gets "cleaned up" by the next person through.
 *
 * That day has arrived: `SCAN_ROOTS` now includes `scripts` and `test`, so both
 * of these files sit inside the scanner's own search space and the path skip is
 * load-bearing rather than belt-and-braces. `test/forbidden-tokens.test.ts`
 * carries known-violating samples and would fail the scan without it.
 */
export const EXCLUDED = new Set([
  "scripts/forbidden-tokens.mjs",
  "test/forbidden-tokens.test.ts",
]);

/**
 * The directories that get scanned.
 *
 * Named explicitly rather than walking from the repository root. `SKIP_DIRS`
 * below does not list `.planning`, and `SCANNED_EXTENSIONS` includes both JSON
 * forms, so a root-level walk would traverse every planning artifact and any
 * generated graph JSON — slower on every commit, and prone to firing a rule on
 * a document that is *describing* the ban rather than violating it.
 *
 * `scripts` and `test` are here because a rule that is never run over a
 * directory is indistinguishable from no rule at all: before this, a banned
 * token outside `src/` was not merely unenforced, it was invisible.
 */
const SCAN_ROOTS = ["src", "scripts", "test"];

/** Directories never worth walking. */
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".husky",
  "dist",
  "build",
  ".wrangler",
  "coverage",
]);

/** Extensions that can plausibly carry a banned token. */
const SCANNED_EXTENSIONS = [
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".jsonc",
];

/** Repo-relative, forward-slashed, so results are identical on any platform. */
function toRepoRelative(absolutePath) {
  return relative(REPO_ROOT, absolutePath).split(sep).join("/");
}

/**
 * Every scannable file under `absoluteDir`, repo-relative.
 *
 * Directory entries are sorted before recursing so the walk order is fixed
 * rather than inherited from the filesystem. The final result is sorted too --
 * this is belt-and-braces for the same reason `EXCLUDED` is.
 */
function walk(absoluteDir, collected = []) {
  let entries;
  try {
    entries = readdirSync(absoluteDir);
  } catch {
    return collected;
  }
  for (const entry of entries.slice().sort()) {
    if (SKIP_DIRS.has(entry)) continue;
    const absolute = join(absoluteDir, entry);
    let stats;
    try {
      stats = statSync(absolute);
    } catch {
      continue;
    }
    if (stats.isDirectory()) {
      walk(absolute, collected);
    } else if (SCANNED_EXTENSIONS.some((ext) => entry.endsWith(ext))) {
      collected.push(absolute);
    }
  }
  return collected;
}

/**
 * `text` with every whole-line comment blanked to spaces.
 *
 * Blanked: a line whose first non-space characters are `//`, and a block
 * comment that starts a line, through its closing `*` + `/` (the rest of that
 * closing line is kept). Every newline and every other character stays where
 * it was, so a match position in the result is the same line and column in
 * `text`.
 *
 * Deliberately line-anchored rather than a tokenizer. A `//` or an opener in
 * the middle of a line may sit inside a string or a regex literal, and reading
 * one of those as a comment would blank real code. So a comment trailing code
 * is kept, and so is a block comment opened after code. Used by the two
 * mutating-path counts only.
 *
 * @param {string} text
 * @returns {string}
 */
export function withoutCommentLines(text) {
  const blank = (part) => part.replace(/[^\n]/g, " ");
  const lines = text.split("\n");
  let inBlock = false;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    // Where to look for the block's close on this line.
    let searchFrom = 0;
    if (!inBlock) {
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//")) {
        lines[i] = blank(line);
        continue;
      }
      if (!trimmed.startsWith("/*")) continue;
      // Past the opener, so the opener's own star cannot close it.
      searchFrom = line.indexOf("/*") + 2;
    }
    const close = line.indexOf("*/", searchFrom);
    if (close === -1) {
      inBlock = true;
      lines[i] = blank(line);
      continue;
    }
    inBlock = false;
    lines[i] = blank(line.slice(0, close + 2)) + line.slice(close + 2);
  }
  return lines.join("\n");
}

/** Line and 1-based column of a character offset within `text`. */
function positionOf(text, index) {
  const before = text.slice(0, index);
  const line = before.split("\n").length;
  const lastNewline = before.lastIndexOf("\n");
  return { line, column: index - lastNewline };
}

/**
 * Match one rule against one file's contents.
 *
 * Matching is done over the whole file rather than line by line, so a logging
 * call split across several lines is still caught.
 *
 * Exported so a scope test can drive the REAL prefix mechanism rather than
 * restating `startsWith` in the test file. A test that asserts `rule.scope`
 * equals a string would keep passing if this function stopped honouring scope
 * altogether, which is the one failure a scope test exists to catch.
 */
export function matchRule(rule, ruleIndex, relativePath, contents) {
  if (rule.scope && !relativePath.startsWith(rule.scope)) return [];
  const found = [];
  // A fresh regex per file: `lastIndex` on a shared global regex is state, and
  // shared state is how a scanner starts skipping matches depending on the
  // order files happened to be read.
  const flags = rule.pattern.flags.includes("g")
    ? rule.pattern.flags
    : `${rule.pattern.flags}g`;
  const pattern = new RegExp(rule.pattern.source, flags);
  let match;
  while ((match = pattern.exec(contents)) !== null) {
    const { line, column } = positionOf(contents, match.index);
    found.push({
      file: relativePath,
      line,
      column,
      pattern: rule.id,
      patternIndex: ruleIndex,
      why: rule.why,
    });
    if (match[0].length === 0) pattern.lastIndex += 1;
  }
  return found;
}

/**
 * Scan one root or several (repo-relative) and return every violation.
 *
 * `roots` takes a single string or a list. The single-string form is the one
 * the tests lean on — `scan("scripts")` and `scan("test")` each scan one
 * directory in isolation, which is how the deleted-choke-point direction and
 * the load-bearing self-exclusion cases are exercised against a real tree
 * rather than a synthetic list. Defaulting to `SCAN_ROOTS` rather than to a
 * single directory is what makes the no-argument call the *same* scan the CLI
 * runs, so a test asserting on `scan()` is asserting on the commit gate itself
 * rather than on a narrower cousin of it.
 *
 * The socket-ownership check runs exactly ONCE over the importers found across
 * all roots. Running it per-root would report the choke-point missing for every
 * root that legitimately contains no socket code — which is every root but one.
 *
 * The result is sorted by file, then line, then column, then rule index, so two
 * runs over the same tree produce byte-identical output regardless of the order
 * the filesystem hands back directory entries. The hook and the test both
 * depend on that: a scan whose output moves around is one whose failures get
 * dismissed as flake.
 */
export function scan(roots = SCAN_ROOTS, { excluded = EXCLUDED } = {}) {
  const rootList = typeof roots === "string" ? [roots] : [...roots];
  const files = [];
  const seenFiles = new Set();
  for (const root of rootList) {
    for (const absolute of walk(resolve(REPO_ROOT, root))) {
      // Nested or repeated roots must not double-report a file, and must not
      // double-count it as a socket importer.
      if (seenFiles.has(absolute)) continue;
      seenFiles.add(absolute);
      files.push(absolute);
    }
  }
  const violations = [];
  const socketImporters = [];
  const davHostResolvers = [];
  const davNetworkCallers = [];
  const appenders = [];
  const subscriptionFeedFetchCallers = [];
  const propsReaders = [];
  const passwordReaderImporters = [];
  const addressHashers = [];
  const principalConstructors = [];
  const confirmLineComposers = [];
  const mutatingOpens = [];
  const mutatingSessionImporters = [];
  const davWriteExports = {};

  for (const absolute of files) {
    const relativePath = toRepoRelative(absolute);
    if (excluded.has(relativePath)) continue;

    let contents;
    try {
      contents = readFileSync(absolute, "utf8");
    } catch {
      continue;
    }

    for (const [ruleIndex, rule] of FORBIDDEN.entries()) {
      violations.push(...matchRule(rule, ruleIndex, relativePath, contents));
    }

    const socketIndex = contents.search(SOCKET_IMPORT);
    if (socketIndex !== -1) {
      socketImporters.push({ file: relativePath, ...positionOf(contents, socketIndex) });
    }

    // Each count constraint collects from its own tree, for the reasons its
    // docstring gives. `String.prototype.search` ignores `lastIndex`, so these
    // carry none of the shared-state hazard `matchRule` guards against.
    if (relativePath.startsWith(DAV_HOST_SCOPE)) {
      const hostIndex = contents.search(DAV_HOST_LITERAL);
      if (hostIndex !== -1) {
        davHostResolvers.push({ file: relativePath, ...positionOf(contents, hostIndex) });
      }
    }
    if (relativePath.startsWith(DAV_FETCH_SCOPE)) {
      const fetchIndex = contents.search(DAV_FETCH_CALL);
      if (fetchIndex !== -1) {
        davNetworkCallers.push({ file: relativePath, ...positionOf(contents, fetchIndex) });
      }
    }
    if (relativePath.startsWith(APPEND_SCOPE)) {
      const appendIndex = contents.search(APPEND_COMMAND);
      if (appendIndex !== -1) {
        appenders.push({ file: relativePath, ...positionOf(contents, appendIndex) });
      }
    }
    if (relativePath.startsWith(SUBSCRIPTION_FEED_FETCH_SCOPE)) {
      const feedFetchIndex = contents.search(SUBSCRIPTION_FEED_FETCH_CALL);
      if (feedFetchIndex !== -1) {
        subscriptionFeedFetchCallers.push({
          file: relativePath,
          ...positionOf(contents, feedFetchIndex),
        });
      }
    }
    if (relativePath.startsWith(PROPS_READER_SCOPE)) {
      const propsReadIndex = contents.search(PROPS_READER);
      if (propsReadIndex !== -1) {
        propsReaders.push({ file: relativePath, ...positionOf(contents, propsReadIndex) });
      }
    }
    // The principal module is not skipped: it defines the reader and imports
    // nothing, so the pattern cannot match it.
    if (relativePath.startsWith(PASSWORD_READER_SCOPE)) {
      const passwordImportIndex = contents.search(PASSWORD_READER_IMPORT);
      if (passwordImportIndex !== -1) {
        passwordReaderImporters.push({
          file: relativePath,
          ...positionOf(contents, passwordImportIndex),
        });
      }
    }
    if (relativePath.startsWith(ADDRESS_HASH_SCOPE)) {
      const addressHashIndex = contents.search(ADDRESS_HASH);
      if (addressHashIndex !== -1) {
        addressHashers.push({
          file: relativePath,
          ...positionOf(contents, addressHashIndex),
        });
      }
    }
    // The principal module is not skipped: it DEFINES the constructor, and the
    // declaration keyword in front of the definition is what the pattern's
    // lookbehind refuses, so it cannot match there.
    if (relativePath.startsWith(PRINCIPAL_CONSTRUCTOR_SCOPE)) {
      const constructorIndex = contents.search(PRINCIPAL_CONSTRUCTOR);
      if (constructorIndex !== -1) {
        principalConstructors.push({
          file: relativePath,
          ...positionOf(contents, constructorIndex),
        });
      }
    }
    // The confirm module is not skipped: it DEFINES the composer, and the
    // definition is precisely what this pattern looks for -- so the owner is
    // expected to be the one entry in the list rather than an exception to it.
    if (relativePath.startsWith(CONFIRM_LINE_SCOPE)) {
      // EVERY match, not the first. Two definitions in the OWNER file are two
      // registers exactly as two files are, and `search()` cannot tell one from
      // two -- so it reported the owner once, the checker skipped it, and "one
      // composer, at one definition site" was false with the scan green. The
      // global copy is built fresh per file because a shared one carries
      // `lastIndex` across files.
      for (const match of contents.matchAll(
        new RegExp(CONFIRM_LINE_COMPOSER, "g"),
      )) {
        confirmLineComposers.push({
          file: relativePath,
          ...positionOf(contents, match.index),
        });
      }
    }
    // The service module is not skipped: it holds the one mutating open, so it
    // is expected to be the one entry. EVERY match, for the reason the
    // confirm-line collector gives: `search()` cannot tell one site in the
    // owner file from two. A fresh global copy per file, so no `lastIndex`
    // travels between files.
    mutatingOpens.push(...collectMutatingOpens(relativePath, contents));
    // The service module defines the orchestrator and imports nothing from
    // itself, so the pattern cannot match there.
    mutatingSessionImporters.push(
      ...collectMutatingSessionImports(relativePath, contents),
    );
    // The write-module manifest collects NAMES rather than a match position, so
    // it is the one collector that keys by module instead of appending to a list.
    // A declared module that is never walked therefore has no key at all, which
    // is what makes the stale arm fire once per manifest name for it.
    if (Object.hasOwn(DAV_WRITE_MODULES, relativePath)) {
      davWriteExports[relativePath] = exportedFunctionNames(contents);
    }
  }

  violations.push(...checkSocketOwnership(socketImporters));
  violations.push(...checkDavHostOwnership(davHostResolvers));
  violations.push(...checkDavFetchOwnership(davNetworkCallers));
  violations.push(...checkAppendOwnership(appenders));
  violations.push(
    ...checkSubscriptionFeedFetchOwnership(subscriptionFeedFetchCallers),
  );
  violations.push(...checkPropsReaderOwnership(propsReaders));
  violations.push(...checkPasswordReaderOwnership(passwordReaderImporters));
  violations.push(...checkAddressHashOwnership(addressHashers));
  violations.push(...checkPrincipalConstructorOwnership(principalConstructors));
  violations.push(...checkConfirmLineOwnership(confirmLineComposers));
  violations.push(...checkMutatingOpenOwnership(mutatingOpens));
  violations.push(
    ...checkMutatingSessionImportOwnership(mutatingSessionImporters),
  );
  violations.push(...checkDavWriteCoverage(davWriteExports));

  return violations.sort(
    (a, b) =>
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.column - b.column ||
      a.patternIndex - b.patternIndex,
  );
}

/**
 * The count constraint, as a pure function over a list of importers.
 *
 * Split out from `scan()` so both of its failure directions can be exercised
 * without materialising a fixture tree on disk. Both directions are failures: a
 * silently-deleted choke-point guards nothing, and a second importer defeats the
 * ban without touching the signature that is supposed to express it.
 *
 * @param {Array<{file: string, line: number, column: number}>} importers
 */
export function checkSocketOwnership(importers) {
  const violations = [];
  for (const importer of importers) {
    if (importer.file === SOCKET_OWNER) continue;
    violations.push({
      file: importer.file,
      line: importer.line,
      column: importer.column,
      pattern: "socket-choke-point-duplicated",
      patternIndex: FORBIDDEN.length,
      why: `The raw socket API may be reached from exactly one file, ${SOCKET_OWNER}, whose connectImap() takes no parameters so host, port, and transport mode are unspeakable at every call site. A second importer defeats that without touching the signature.`,
    });
  }
  if (importers.length === 0) {
    violations.push({
      file: SOCKET_OWNER,
      line: 0,
      column: 0,
      pattern: "socket-choke-point-missing",
      patternIndex: FORBIDDEN.length + 1,
      why: `No file under the scanned root reaches the raw socket API. A silently-deleted choke-point is as much a failure as a duplicated one: it means ${SOCKET_OWNER} was moved, renamed, or emptied and the ban now guards nothing.`,
    });
  }
  return violations;
}

/**
 * The host-resolution count, as a pure function over a list of resolvers.
 *
 * Same split, and for the same reason: both failure directions are exercised
 * against a list rather than against a fixture tree on disk. See the
 * `DAV_HOST_LITERAL` docstring for why this is a count at all.
 *
 * @param {Array<{file: string, line: number, column: number}>} resolvers
 */
export function checkDavHostOwnership(resolvers) {
  const violations = [];
  for (const resolver of resolvers) {
    if (resolver.file === DAV_HOST_OWNER) continue;
    violations.push({
      file: resolver.file,
      line: resolver.line,
      column: resolver.column,
      pattern: "dav-host-outside-discovery",
      patternIndex: FORBIDDEN.length + 2,
      why: `A fixed iCloud DAV hostname outside ${DAV_HOST_OWNER}. No constant naming one may be used for anything past the initial discovery PROPFIND: the partition number in a home URL is per-account AND per-service, and Apple has moved accounts between partitions with no notice, breaking previously-working clients account-wide. Resolve the home URL through discovery and pass it down; do not copy one out of a diagnostic.`,
    });
  }
  if (resolvers.length === 0) {
    violations.push({
      file: DAV_HOST_OWNER,
      line: 0,
      column: 0,
      pattern: "dav-host-resolution-missing",
      patternIndex: FORBIDDEN.length + 3,
      why: `No file under the scanned tree names an iCloud DAV hostname, which means ${DAV_HOST_OWNER} was moved, renamed, or emptied. This is the direction a scoped negative cannot see: "no hardcoded host" is trivially true of a codebase that no longer resolves a host at all, and therefore no longer works.`,
    });
  }
  return violations;
}

/**
 * The DAV transport count, as a pure function over a list of callers.
 *
 * @param {Array<{file: string, line: number, column: number}>} callers
 */
export function checkDavFetchOwnership(callers) {
  const violations = [];
  for (const caller of callers) {
    if (caller.file === DAV_FETCH_OWNER) continue;
    violations.push({
      file: caller.file,
      line: caller.line,
      column: caller.column,
      pattern: "dav-fetch-outside-transport",
      patternIndex: FORBIDDEN.length + 4,
      why: `A bare network call under ${DAV_FETCH_SCOPE} outside ${DAV_FETCH_OWNER}. That module attaches the per-call credential, forces the manual redirect policy, classifies the status number, and serialises the request; a second caller defeats all four at once and does it silently. Take the injected transport as a parameter and call that instead.`,
    });
  }
  if (callers.length === 0) {
    violations.push({
      file: DAV_FETCH_OWNER,
      line: 0,
      column: 0,
      pattern: "dav-fetch-choke-point-missing",
      patternIndex: FORBIDDEN.length + 5,
      why: `No file under ${DAV_FETCH_SCOPE} reaches the network, which means ${DAV_FETCH_OWNER} was moved, renamed, or emptied. A choke point that no longer exists guards nothing, and that failure is far easier to miss than a duplicated one.`,
    });
  }
  return violations;
}

/**
 * The write choke point, as a pure function over a list of appenders.
 *
 * Same split as the three above, and for the same reason: both failure
 * directions are exercised against a list rather than against a fixture tree on
 * disk. See the `APPEND_COMMAND` docstring for why this is a count at all, and
 * for the property it deliberately does not hold.
 *
 * @param {Array<{file: string, line: number, column: number}>} appenders
 */
export function checkAppendOwnership(appenders) {
  const violations = [];
  for (const appender of appenders) {
    if (appender.file === APPEND_OWNER) continue;
    violations.push({
      file: appender.file,
      line: appender.line,
      column: appender.column,
      pattern: "append-outside-drafts",
      patternIndex: FORBIDDEN.length + 6,
      why: `A second module under ${APPEND_SCOPE} constructs the write command, outside ${APPEND_OWNER}. Placing a message into the drafts folder is this project's entire write path and is deliberately its entire write path: Claude drafts, the human reviews and sends, and that human step is the backstop against prompt-injected content in an email reaching an outbound message. A second write path is a decision rather than a refactor -- call the existing one instead, and if it genuinely will not serve, say so and get the decision.`,
    });
  }
  if (appenders.length === 0) {
    violations.push({
      file: APPEND_OWNER,
      line: 0,
      column: 0,
      pattern: "append-choke-point-missing",
      patternIndex: FORBIDDEN.length + 7,
      why: `No file under ${APPEND_SCOPE} constructs the write command, which means ${APPEND_OWNER} was moved, renamed, or emptied. This is the direction a scoped negative cannot see: "no second write path" is trivially true of a codebase that has no write path at all, and the capability would be gone with nothing reporting its absence.`,
    });
  }
  return violations;
}

/**
 * The subscription-feed fetch choke point, as a pure function over a list of
 * callers.
 *
 * Same split as the three DAV/APPEND counts above, and for the same reason:
 * both failure directions are exercised against a list rather than against a
 * fixture tree on disk. See the `SUBSCRIPTION_FEED_FETCH_CALL` docstring for
 * why this is a count at all.
 *
 * @param {Array<{file: string, line: number, column: number}>} callers
 */
export function checkSubscriptionFeedFetchOwnership(callers) {
  const violations = [];
  for (const caller of callers) {
    if (caller.file === SUBSCRIPTION_FEED_FETCH_OWNER) continue;
    violations.push({
      file: caller.file,
      line: caller.line,
      column: caller.column,
      pattern: "subscription-feed-fetch-outside-owner",
      patternIndex: FORBIDDEN.length + 8,
      why: `A bare network call under ${SUBSCRIPTION_FEED_FETCH_SCOPE} outside ${SUBSCRIPTION_FEED_FETCH_OWNER}. That module fetches a CS:source href with NO credential attached, deliberately -- the href names an arbitrary third-party host the account does not control, and a second caller reaching the network directly under this scope risks posting the iCloud Basic credential to that stranger's server via some other code path. Take the injected fetcher as a parameter and call that instead.`,
    });
  }
  if (callers.length === 0) {
    violations.push({
      file: SUBSCRIPTION_FEED_FETCH_OWNER,
      line: 0,
      column: 0,
      pattern: "subscription-feed-fetch-choke-point-missing",
      patternIndex: FORBIDDEN.length + 9,
      why: `No file under ${SUBSCRIPTION_FEED_FETCH_SCOPE} reaches the network, which means ${SUBSCRIPTION_FEED_FETCH_OWNER} was moved, renamed, or emptied. A choke point that no longer exists guards nothing, and that failure is far easier to miss than a duplicated one.`,
    });
  }
  return violations;
}

/**
 * The single reader of the grant's props, as a pure function over a list of
 * readers.
 *
 * Same split as the counts above, and for the same reason: both failure
 * directions are exercised against a list rather than against a fixture tree
 * on disk. See the `PROPS_READER` docstring for why this is a count at all,
 * what it does not see, and what Phase 11 must add.
 *
 * @param {Array<{file: string, line: number, column: number}>} readers
 */
export function checkPropsReaderOwnership(readers) {
  const violations = [];
  for (const reader of readers) {
    if (reader.file === PROPS_READER_OWNER) continue;
    violations.push({
      file: reader.file,
      line: reader.line,
      column: reader.column,
      pattern: "props-reader-outside-owner",
      patternIndex: FORBIDDEN.length + 10,
      why: `A read of the grant's props under ${PROPS_READER_SCOPE} outside ${PROPS_READER_OWNER}. That file is the door: it checks the grant is the owner's, answers every other grant with a 401, and hands the tool layer a promise of the principal. A second reader is a second place that decides who the caller is, and it can serve a grant the door would refuse. Route the read through the door: take the principal it passes down, and do not read the grant again. If this fired on a comment, write "the grant's props" and not the spelled read. Do not narrow the pattern.`,
    });
  }
  if (readers.length === 0) {
    violations.push({
      file: PROPS_READER_OWNER,
      line: 0,
      column: 0,
      pattern: "props-reader-missing",
      patternIndex: FORBIDDEN.length + 11,
      why: `No file under ${PROPS_READER_SCOPE} reads the grant's props, which means the owner guard in ${PROPS_READER_OWNER} was deleted, moved, or rewritten into a form this count cannot see. A door that never reads the grant serves every grant, and nothing fails on the way out. Restore the owner guard in that file, reading the props off the request context by its usual name.`,
    });
  }
  return violations;
}

/**
 * The two readers of the password, as a pure function over a list of
 * importers.
 *
 * Same split as the counts above, but NOT the same body: this count has two
 * owners. See the `PASSWORD_READER_IMPORT` docstring for why.
 *
 * @param {Array<{file: string, line: number, column: number}>} importers
 */
export function checkPasswordReaderOwnership(importers) {
  const violations = [];
  const owners = PASSWORD_READER_OWNERS.join(" and ");
  for (const importer of importers) {
    if (PASSWORD_READER_OWNERS.includes(importer.file)) continue;
    violations.push({
      file: importer.file,
      line: importer.line,
      column: importer.column,
      pattern: "password-reader-outside-owners",
      patternIndex: FORBIDDEN.length + 12,
      why: `An import of the password reader under ${PASSWORD_READER_SCOPE} outside ${owners}. Those two files are the only places a password is spent: one writes the mail login, the other builds the DAV authorization header. A third importer is a second thing in this project that can read a password, arriving without a decision. Do not read the password here. Hand the principal to one of the two owners and let it do the login. Do not reach the reader another way (a namespace import, a re-export, a dynamic import, an alias), and do not narrow the pattern. If this fired on a comment, describe the import in plain words.`,
    });
  }
  // One per absent owner, not one for an empty list: each owner is its own
  // login path, and losing either is its own failure.
  for (const owner of PASSWORD_READER_OWNERS) {
    if (importers.some((importer) => importer.file === owner)) continue;
    violations.push({
      file: owner,
      line: 0,
      column: 0,
      pattern: "password-reader-missing",
      patternIndex: FORBIDDEN.length + 13,
      why: `${owner} no longer imports the password reader from the principal module, which means that login path was deleted, moved, or rewritten to get the password some other way this count cannot see. Nothing fails on the way out when a login path leaves, and a path that reads the password another way is unguarded. Restore the plain named import of the reader in ${owner}. If the login path really moved, that is a change to the safety boundary: get a decision, then change the owner list, never the pattern.`,
    });
  }
  return violations;
}

/**
 * The one site that turns an address into a user id, as a pure function over a
 * list of hashing sites.
 *
 * Same split and same shape as the mail-secret count above: one owner, both
 * failure directions exercised against a list rather than a fixture tree on
 * disk. See the `ADDRESS_HASH` docstring for why this is a count at all, why
 * the anchor names the encoder, why the word boundary and the absence of a
 * case-insensitive flag are both mandatory, and what it does not see.
 *
 * @param {Array<{file: string, line: number, column: number}>} hashers
 */
export function checkAddressHashOwnership(hashers) {
  const violations = [];
  for (const hasher of hashers) {
    if (hasher.file === ADDRESS_HASH_OWNER) continue;
    violations.push({
      file: hasher.file,
      line: hasher.line,
      column: hasher.column,
      pattern: "address-hashing-site-outside-owner",
      patternIndex: FORBIDDEN.length + 14,
      why: `A second site under ${ADDRESS_HASH_SCOPE} turns an address into a user id, outside ${ADDRESS_HASH_OWNER}. That file holds the one producer of the id every store key in this project is scoped by (ISO-05 rule 10, D-14, D-18). Two producers drift, and the day they disagree one person becomes two users or two people become one: a user whose id moved loses every staged attachment and every pending confirmation in a single deploy, and two users who collapsed onto one id read each other's. Delete this hashing and read the id off the signed-in principal instead, which is what every other caller in the tree does. Do not narrow the pattern and do not rename the encoder to hide the site.`,
    });
  }
  if (hashers.length === 0) {
    violations.push({
      file: ADDRESS_HASH_OWNER,
      line: 0,
      column: 0,
      pattern: "address-hashing-site-missing",
      patternIndex: FORBIDDEN.length + 15,
      why: `No site under ${ADDRESS_HASH_SCOPE} turns an address into a user id, which means the one producer in ${ADDRESS_HASH_OWNER} was deleted, renamed, or rewritten into a form this count cannot see. Zero producers is as much a violation as two, and it is the quieter of the pair: nothing goes red on the way out, because the tests that covered the deleted code leave with it. Restore the hashing in that file, and keep the module-scope encoder named as it is — this count finds its owner by that spelling, and the tell of a rename is a digest call still present while this count reads zero. If the producer really moved, that is a change to the safety boundary: get a decision, then change the owner, never the pattern.`,
    });
  }
  return violations;
}

/**
 * The two sites that mint a principal from props, as a pure function over a
 * list of callers.
 *
 * Same split as the counts above, and NOT the same body as the one-owner ones:
 * this count has two owners, so its missing arm fires once per absent owner in
 * the same shape the password count uses. See the `PRINCIPAL_CONSTRUCTOR`
 * docstring for why there are legitimately two, why it is a separate count
 * rather than an arm on the props-reader count, and what it does not see.
 *
 * @param {Array<{file: string, line: number, column: number}>} callers
 */
export function checkPrincipalConstructorOwnership(callers) {
  const violations = [];
  const owners = PRINCIPAL_CONSTRUCTOR_OWNERS.join(" and ");
  for (const caller of callers) {
    if (PRINCIPAL_CONSTRUCTOR_OWNERS.includes(caller.file)) continue;
    violations.push({
      file: caller.file,
      line: caller.line,
      column: caller.column,
      pattern: "principal-constructor-outside-owners",
      patternIndex: FORBIDDEN.length + 16,
      why: `A call to the props-backed principal constructor under ${PRINCIPAL_CONSTRUCTOR_SCOPE} outside ${owners}. Those two files are the only places a principal is minted: the first builds one from a stored grant's props, which the door has already checked against the allow list, and the second builds one from values a person just typed, because no grant exists yet and the password reader answers only the very object this constructor built. A third minting site is a third place in this project that can turn a props object into a live session, and the props it is handed need not be the props the door checked — so it can act for somebody the door would have refused. Do not mint a principal here. Take the one the door passed down, or hand your props to the door. If a third site genuinely belongs, that is a change to the safety boundary and not a refactor: get a decision, then change the owner list, never the pattern. If this fired on a comment, describe the construction in plain words or name the constructor without a parenthesis after it.`,
    });
  }
  // One per absent owner, not one for an empty list: each owner is its own
  // identity path, built from its own source, and losing either is its own
  // failure.
  for (const owner of PRINCIPAL_CONSTRUCTOR_OWNERS) {
    if (callers.some((caller) => caller.file === owner)) continue;
    violations.push({
      file: owner,
      line: 0,
      column: 0,
      pattern: "principal-constructor-missing",
      patternIndex: FORBIDDEN.length + 17,
      why: `${owner} no longer calls the props-backed principal constructor, which means that identity path was deleted, moved, or rewritten to get identity some other way this count cannot see. Zero callers is as much a violation as three, and it is the quieter of the pair: nothing goes red on the way out, because the tests that covered the deleted code leave with it. The specific regression this arm exists to catch is the one Phase 11 spent a whole phase making impossible — identity read back out of the Worker environment instead of out of the grant, which serves the wrong person's mail to whoever still holds a token. Restore the plain named call in ${owner}. If the identity path really moved, that is a change to the safety boundary: get a decision, then change the owner list, never the pattern.`,
    });
  }
  return violations;
}

/**
 * The one site that composes the human-facing line, as a pure function over a
 * list of definitions.
 *
 * Same split as the one-owner counts above, and the same body: split out from
 * `scan()` so both of its failure directions can be exercised without
 * materialising a fixture tree on disk. See the `CONFIRM_LINE_COMPOSER`
 * docstring for why this is a count rather than a negative, and for the five
 * shapes it cannot see.
 *
 * **The owner is permitted ONE definition and not "any number of them".** The
 * first occurrence in the owner file is the composer; a second is a second
 * register in the same file, which is the same failure as a second file and gets
 * the same id. The collector's `matchAll` is what makes this measurable at all
 * -- while it used `search()`, a file contributed at most one entry and this loop
 * could not have told the two apart.
 *
 * @param {Array<{file: string, line: number, column: number}>} composers
 */
export function checkConfirmLineOwnership(composers) {
  const violations = [];
  let ownerDefinitions = 0;
  for (const composer of composers) {
    if (composer.file === CONFIRM_LINE_OWNER) {
      ownerDefinitions += 1;
      if (ownerDefinitions === 1) continue;
    }
    violations.push({
      file: composer.file,
      line: composer.line,
      column: composer.column,
      pattern: "confirm-line-composer-duplicated",
      patternIndex: FORBIDDEN.length + 21,
      why: `A second definition of the composer for the human-facing confirmation line -- either in another module under ${CONFIRM_LINE_SCOPE}, or a second one inside ${CONFIRM_LINE_OWNER} itself, which counts the same and used to pass. That sentence is the one thing the confirmation token cannot bind: the token proves this server applied exactly the change it previewed, and proves nothing at all about what the user was told before they agreed. CONF-04 answers that by having this server write the sentence, which only works while there is ONE of it -- two composers are two registers, and the drift between them is invisible until somebody reads two transcripts side by side. Call ${CONFIRM_LINE_OWNER}'s composer and pass it a resolved summary; do not phrase a line here. If a second composer genuinely belongs, that is a change to the safety boundary and not a refactor: get a decision, then change the owner, never the pattern. If this fired on a comment, name the composer without a declaration keyword in front of it.`,
    });
  }
  if (composers.length === 0) {
    violations.push({
      file: CONFIRM_LINE_OWNER,
      line: 0,
      column: 0,
      pattern: "confirm-line-composer-missing",
      patternIndex: FORBIDDEN.length + 22,
      why: `No file under ${CONFIRM_LINE_SCOPE} defines a composer for the human-facing confirmation line, which means ${CONFIRM_LINE_OWNER}'s was deleted, renamed, or inlined back into its call sites. Zero composers is as much a violation as two, and it is the quieter of the pair: nothing goes red on the way out, because the tests that covered the deleted code leave with it. What that loses is the whole of CONF-04 -- the sentence a person reads before agreeing to a destructive change goes back to being written by a model that is reading stranger-authored content in the same context window, which is the residual attack PITFALLS #40 describes: preview a real delete, describe it inaccurately, get a yes, commit honestly, and every mechanical check passes. Restore the definition in ${CONFIRM_LINE_OWNER}. If the composer really moved, that is a change to the safety boundary: get a decision, then change the owner, never the pattern.`,
    });
  }
  return violations;
}

/**
 * The one mutating open, as a pure function over a list of construction sites.
 *
 * The confirm-line checker's body, because the owner is permitted ONE site and
 * not "any number of them": a second open inside the owner file is a second
 * site and gets the same id as a second file. See the `MUTATING_OPEN_COMMAND`
 * docstring for why this is a count and for the three shapes it cannot see.
 *
 * @param {Array<{file: string, line: number, column: number}>} sites
 */
export function checkMutatingOpenOwnership(sites) {
  const violations = [];
  let ownerSites = 0;
  for (const site of sites) {
    if (site.file === MUTATING_OPEN_OWNER) {
      ownerSites += 1;
      if (ownerSites === 1) continue;
    }
    violations.push({
      file: site.file,
      line: site.line,
      column: site.column,
      pattern: "mutating-open-duplicated",
      patternIndex: FORBIDDEN.length + 23,
      why: `A second construction site of the mutating mailbox open -- either in another module under ${MUTATING_OPEN_SCOPE}, or a second one inside ${MUTATING_OPEN_OWNER} itself, which counts the same. Every read opens its mailbox read-only, and exactly one place builds the open that lets the server change a mailbox: inside withMutatingMailboxOver, behind its own session type and its own access check. A second site is a second way to reach a mailbox opened for changing, arriving without a decision, which is the PITFALLS #32 failure. Call a verb in src/mail/triage.ts instead. If a second site genuinely belongs, that is a decision on the safety boundary, not a refactor: get the decision, then change the owner, never the pattern.`,
    });
  }
  if (sites.length === 0) {
    violations.push({
      file: MUTATING_OPEN_OWNER,
      line: 0,
      column: 0,
      pattern: "mutating-open-missing",
      patternIndex: FORBIDDEN.length + 24,
      why: `No file under ${MUTATING_OPEN_SCOPE} builds the mutating mailbox open, which means the site in ${MUTATING_OPEN_OWNER} was deleted, renamed, or emptied. Zero is as much a violation as two, and it is the quieter of the pair: nothing goes red on the way out, because the tests that covered the deleted code leave with it. Restore the open inside withMutatingMailboxOver. If it really moved, that is a change to the safety boundary: get a decision, then change the owner, never the pattern.`,
    });
  }
  return violations;
}

/**
 * The one importer of the mutating orchestrator, as a pure function over a list
 * of importers.
 *
 * The write choke point's body: one owner, a non-owner is reported, and an
 * empty list is the missing arm. See the `MUTATING_SESSION_IMPORT` docstring for
 * why this is a count and for the four shapes it cannot see.
 *
 * @param {Array<{file: string, line: number, column: number}>} importers
 */
export function checkMutatingSessionImportOwnership(importers) {
  const violations = [];
  for (const importer of importers) {
    if (importer.file === MUTATING_SESSION_OWNER) continue;
    violations.push({
      file: importer.file,
      line: importer.line,
      column: importer.column,
      pattern: "mutating-session-importer-outside-triage",
      patternIndex: FORBIDDEN.length + 25,
      why: `An import of the mutating orchestrator under ${MUTATING_SESSION_SCOPE} outside ${MUTATING_SESSION_OWNER}. That module is the only place allowed to hold a mailbox opened for changing, and it exports narrow verbs -- one message, one flag, no body fetch -- never a session. A second importer skips those verbs and can do anything to the mailbox it holds. Call a verb from ${MUTATING_SESSION_OWNER} instead, or add one there. Do not reach the orchestrator another way (a namespace import, a re-export, a dynamic import, an alias). A second importer is a decision on the safety boundary, not a refactor: get the decision, then change the owner, never the pattern.`,
    });
  }
  if (importers.length === 0) {
    violations.push({
      file: MUTATING_SESSION_OWNER,
      line: 0,
      column: 0,
      pattern: "mutating-session-importer-missing",
      patternIndex: FORBIDDEN.length + 26,
      why: `No file under ${MUTATING_SESSION_SCOPE} imports the mutating orchestrator, which means ${MUTATING_SESSION_OWNER} was deleted, renamed, emptied, or rewired to reach it some other way. Zero is as much a violation as two: "no second importer" is trivially true of a tree where the verbs are gone, and nothing reports their absence. Restore the import in ${MUTATING_SESSION_OWNER}. If the verbs really moved, that is a change to the safety boundary: get a decision, then change the owner, never the pattern.`,
    });
  }
  return violations;
}

/**
 * The names in the trailing alternation group of the shipped
 * `dav-concurrent-request` rule.
 *
 * Reads the SHIPPED rule out of `FORBIDDEN` rather than a copy of it. That is
 * what makes the unguarded arm below a MEASUREMENT rather than an agreement: a
 * list restated beside the checker would agree with the checker by construction,
 * and dropping a name would drop it from both sides at once.
 *
 * Throws rather than returning an empty set when the group is not found, on the
 * test file's own `alternationNamesOf` precedent. An empty set would mark every
 * guarded name in the manifest unguarded and freeze the repository, and a
 * restructured pattern should fail loudly at the extraction instead.
 *
 * THE PARAMETER IS FOR THE THROW AND FOR NOTHING ELSE. It exists so a test can
 * prove the failure arm fires on a pattern with no trailing group.
 * `checkDavWriteCoverage` calls this with NO argument, so the measured side of
 * its third arm is never substitutable — there is nowhere to feed a convenient
 * alternation, which is what keeps that checker's manifest parameter an injection
 * point rather than a way to make the rule see less.
 *
 * @param {{pattern: RegExp}} [rule]
 * @returns {string[]}
 */
export function davAlternationNames(
  rule = FORBIDDEN.find((entry) => entry.id === "dav-concurrent-request"),
) {
  if (rule === undefined) {
    throw new Error("the dav-concurrent-request rule is not on the ban list");
  }
  const source = rule.pattern.source;
  const open = source.lastIndexOf("(?:");
  const close = source.lastIndexOf(")");
  if (open < 0 || close < open) {
    throw new Error("no trailing alternation group found in the rule's source");
  }
  return source.slice(open + "(?:".length, close).split("|");
}

/**
 * The write-module manifest, as a pure function over what the walk collected.
 *
 * Same split as every count above, and for the same reason: all three failure
 * directions are exercised against a map rather than against a fixture tree on
 * disk. See the `DAV_WRITE_MODULES` docstring for why this is a manifest at all,
 * and for the four shapes the export reader cannot see.
 *
 * THE SECOND PARAMETER EXISTS FOR ONE REASON AND IT IS NOT CONVENIENCE. The
 * third arm compares the MANIFEST against the ALTERNATION. Both are module-level
 * constants, and every manifest-guarded name is already in the shipped
 * alternation, so on a clean tree no value of `collected` can produce that arm —
 * it would be a rule nothing in the suite could ever observe, which is exactly
 * the failure ./.claude/CLAUDE.md's Enforcement section names: a constraint whose
 * arm can never fire looks identical to a constraint that was never added.
 * Substituting the manifest lets a test drive that arm with a fabricated entry
 * whose guarded name the alternation genuinely does not carry.
 *
 * ONLY THE HAND-WRITTEN SIDE IS SUBSTITUTABLE, AND THAT IS THE WHOLE DESIGN.
 * There is no alternation parameter and none may be added:
 * `davAlternationNames()` is called below with no argument, so the third arm
 * always measures the rule that actually ships, even when driven from a
 * fabricated manifest. Exclusion is by PATH in this project and never by
 * weakening a pattern; this is the same discipline applied to a checker.
 *
 * WHAT THE PRODUCTION CALL SITE'S PINNED TEXT DOES NOT PROVE, written down rather
 * than left implied. The suite pins `scan()`'s call as byte-exactly
 * `checkDavWriteCoverage(davWriteExports)` — the accumulator's own identifier, not
 * merely one argument — and pins that identifier's occurrence count at three. That
 * cannot see a narrowing performed INSIDE `exportedFunctionNames`, which the
 * suite's export-reader tests against shipped source hold instead; and it cannot
 * see a declared module added to `EXCLUDED` before the walk reaches it. The second
 * of those is loud rather than quiet: an unwalked module has an empty collected
 * list, so the stale arm fires once per manifest name for it.
 *
 * @param {Record<string, readonly string[]>} collected
 * @param {Record<string, {why: string, exports: Record<string, string>}>} [manifest]
 * @returns {Array<object>}
 */
export function checkDavWriteCoverage(collected, manifest = DAV_WRITE_MODULES) {
  const alternation = new Set(davAlternationNames());
  const violations = [];

  for (const [modulePath, entry] of Object.entries(manifest)) {
    const found = collected[modulePath] ?? [];
    const declared = Object.keys(entry.exports);
    // Exact ASCII string equality on both sides, through a plain Set: no case
    // folding, no Unicode normalisation, no trimming. A name differing from a
    // manifest entry only by case is two different names, and is reported as
    // unmanifested AND as stale in the same run — which is the correct answer,
    // because the export the module actually ships is the one nobody decided
    // about.
    const declaredNames = new Set(declared);
    const foundNames = new Set(found);

    for (const name of found) {
      if (declaredNames.has(name)) continue;
      violations.push({
        file: modulePath,
        line: 0,
        column: 0,
        pattern: "dav-write-export-unmanifested",
        patternIndex: FORBIDDEN.length + 18,
        why: `${modulePath} exports ${name}, and no disposition for that name is recorded in the write-module manifest. A new export in a declared write module is a new entry point nobody has decided about, and "write" is not inferable from a name, so nothing will decide it automatically: ${modulePath} is on that manifest because ${entry.why} Record the name with a disposition — either the exact string "guarded", in which case it must also appear in the dav-concurrent-request alternation, or a written reason saying it issues no request at all. Do not guess from the name: read the function.`,
      });
    }

    for (const name of declared) {
      if (foundNames.has(name)) continue;
      violations.push({
        file: modulePath,
        line: 0,
        column: 0,
        pattern: "dav-write-manifest-stale",
        patternIndex: FORBIDDEN.length + 19,
        why: `The write-module manifest lists ${name} for ${modulePath}, and that module no longer exports it. This is the zero direction, and it is the one a scoped negative cannot see: a module that was moved, renamed, or emptied is never walked at all, its collected export list is empty, and every name the manifest lists for it comes back stale — which is exactly right, because a manifest that matches nothing guards nothing, and that failure is quieter than a duplicate since the tests covering the deleted code leave with it. Either the module moved, in which case change its key, or the export went, in which case drop the name. If the export is still there under a shape the reader cannot see — a re-export, a const arrow, or a name bound and exported separately — that is a gap rather than an alarm, and the manifest's own docstring names all four.`,
      });
    }

    for (const name of declared) {
      if (entry.exports[name] !== "guarded") continue;
      if (alternation.has(name)) continue;
      violations.push({
        file: modulePath,
        line: 0,
        column: 0,
        pattern: "dav-write-entry-point-unguarded",
        patternIndex: FORBIDDEN.length + 20,
        why: `The write-module manifest marks ${name} in ${modulePath} as guarded, and that name is absent from the dav-concurrent-request alternation. Pitfall 65, in this file's own register: a name not in that alternation is invisible to every assertion in the suite — the rule-level set-equality guard included, because that guard operates at the RULE level and cannot see inside one — so an unguarded entry point is indistinguishable from a guarded one by any check that exists. Add the name to the alternation. Never narrow the group to make this pass: a trailing word boundary would make the safety rule match strictly less than it does today, and that is the move the Conventions forbid outright.`,
      });
    }
  }

  return violations;
}

/**
 * The commit-time gate, checked as a property of the repository.
 *
 * A hand-placed hook under `.git/hooks/` is not version-controlled and a fresh
 * clone silently loses it, which is the exact failure the hook exists to
 * prevent. This confirms the tracked file is present, is executable (a hook git
 * cannot run permits everything, which is worse than no hook at all), and still
 * performs both of its checks.
 *
 * Not called from the CLI entry point below: a gate that verifies its own
 * existence from inside itself proves nothing. The test calls it.
 */
export function checkCommitHook(hookPath = ".husky/pre-commit") {
  const absolute = resolve(REPO_ROOT, hookPath);
  const violation = (pattern, why) => ({
    file: hookPath,
    line: 0,
    column: 0,
    pattern,
    patternIndex: 0,
    why,
  });

  let stats;
  try {
    stats = statSync(absolute);
  } catch {
    return [
      violation(
        "commit-gate-missing",
        "The pre-commit hook is absent. D-02 leaves no CI pipeline, so this hook is the only gate between a forbidden token and permanent history.",
      ),
    ];
  }

  const violations = [];
  if ((stats.mode & 0o100) === 0) {
    violations.push(
      violation(
        "commit-gate-not-executable",
        "The pre-commit hook is not executable. Git will skip it silently, so every commit passes and nothing reports that the gate is off.",
      ),
    );
  }

  const contents = readFileSync(absolute, "utf8");
  if (!contents.includes("forbidden-tokens")) {
    violations.push(
      violation(
        "commit-gate-toothless",
        "The pre-commit hook no longer invokes this scanner, so the commit-time layer and the test-time layer have drifted apart.",
      ),
    );
  }
  if (!contents.includes("dev.vars")) {
    violations.push(
      violation(
        "commit-gate-missing-secrets-check",
        "The pre-commit hook no longer refuses a staged local-secrets file. The .gitignore entry alone is defeated by `git add -f`.",
      ),
    );
  }
  if (!/^\s*set -e\b/m.test(contents)) {
    violations.push(
      violation(
        "commit-gate-no-set-e",
        "The pre-commit hook does not abort on error, so a failing scan is discarded and the commit proceeds: in POSIX sh a script exits with the status of its LAST command, and the hook's last command is a conditional that succeeds when it finds nothing. Every violation still prints. Today the gate works only because husky's generated wrapper runs the hook under `sh -e` — a line in a gitignored file the hook does not mention, which disappears if husky is removed, downgraded, replaced, or the hook is run by hand.",
      ),
    );
  }
  return violations;
}

/**
 * Configuration checks the deploy tooling cannot make for us.
 *
 * Wave 1 established that `wrangler deploy --dry-run` does not validate inside a
 * `limits` block: an invalid key there produces no output and exit 0, because
 * wrangler's `additionalProperties: false` lives in its JSON schema for
 * schema-aware editors rather than in the deploy path. So a future session that
 * adds `limits.simultaneousConnections` believing it has configured the
 * six-connection cap gets zero feedback from the tooling and a false sense that
 * the cap is handled -- when the real mitigation is architectural (D-10).
 *
 * The second check keeps the deployed hostname to its single source of truth:
 * `routes[0].pattern` in the config. `scripts/write-hostname.mjs` bakes that
 * value into a generated module (nothing in `src/` can read the config off disk
 * at runtime), and `src/mcp/api-handler.ts` re-exports it. A hardcoded hostname
 * literal reappearing in that file is a second home nothing forces to match the
 * route -- exactly the drift plan 01-02 flagged -- so the check fails on it.
 */
export function scanWranglerConfig(
  configPath = ["wrangler.jsonc.example", "wrangler.jsonc"],
  hostnameSourcePath = "src/mcp/api-handler.ts",
) {
  const readOrNull = (relativePath) => {
    try {
      return readFileSync(resolve(REPO_ROOT, relativePath), "utf8");
    } catch {
      return null;
    }
  };

  const violations = [];

  // The tracked template and the git-ignored real config are both checked when
  // present -- the template is what reviewers see, the real config is what
  // deploys. A fresh checkout has only the template; that is fine.
  const configPaths = Array.isArray(configPath) ? configPath : [configPath];
  for (const path of configPaths) {
    const config = readOrNull(path);
    if (config === null) continue;

    const index = config.search(/simultaneousConnections/);
    if (index !== -1) {
      violations.push({
        file: path,
        ...positionOf(config, index),
        pattern: "nonexistent-limits-key",
        patternIndex: 0,
        why: "`limits.simultaneousConnections` does not exist in wrangler's schema and `wrangler deploy --dry-run` will not tell you so -- it accepts the key silently, so nobody finds out the cap was never configured. The limit is enforced architecturally instead (one live socket per request, no fan-out).",
      });
    }
  }

  const hostnameSource = readOrNull(hostnameSourcePath);
  const hardcoded = hostnameSource
    ? /DEPLOYED_HOSTNAME\s*=\s*["']([^"']+)["']/.exec(hostnameSource)?.[1]
    : undefined;
  if (hardcoded) {
    violations.push({
      file: hostnameSourcePath,
      line: 1,
      column: 1,
      pattern: "hostname-hardcoded",
      patternIndex: 1,
      why: `${hostnameSourcePath} hardcodes a deployed hostname literal (${hardcoded}). The hostname's single source of truth is routes[0].pattern in the wrangler config, baked into src/deployed-hostname.generated.ts by scripts/write-hostname.mjs; re-export it from there. A literal here is a second home nothing forces to match the route, and a mismatch breaks host validation and the OAuth token audience at the same time.`,
    });
  }

  return violations;
}

/** Format one violation the way the hook prints it. */
export function formatViolation(violation) {
  const where = violation.line > 0 ? `${violation.file}:${violation.line}` : violation.file;
  return `${where} — ${violation.why}`;
}

// --------------------------------------------------------------- CLI entry
// Runs when invoked as `node scripts/forbidden-tokens.mjs`, not when imported.
const invokedDirectly =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  // Roots passed explicitly rather than left to the default, so the one place
  // that decides what the commit gate covers reads it at the call site.
  const violations = [...scan(SCAN_ROOTS), ...scanWranglerConfig()];
  if (violations.length > 0) {
    console.error(`Forbidden tokens found (${violations.length}):\n`);
    for (const violation of violations) console.error(`  ${formatViolation(violation)}`);
    console.error(
      "\nThese are safety boundaries, not style rules. See the Conventions section of ./.claude/CLAUDE.md before changing any of them.",
    );
    process.exit(1);
  }
}
