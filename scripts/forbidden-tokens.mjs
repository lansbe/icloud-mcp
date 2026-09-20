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
    why: "A logging call whose arguments mention a secret binding name, or one of the two credential field names the grant's props carry. A log line naming either field leaks the Apple ID or the app-specific password. Credentials must never reach a log, an error, or a tool response.",
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
    why: "No logging call of any kind may exist under src/, not only under src/mail/. The environment binding carries AUTH_SECRET, the Apple ID, and the app-specific password, so one debug line that passes it names no secret and leaks all three -- and observability logging is enabled, so 'a log' means retained Cloudflare storage, not a terminal.",
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
    why: "A logging call whose arguments mention the bare environment object. It carries APPLE_ID and APPLE_APP_PASSWORD, so nothing needs to name a secret for the credentials to reach the log -- which is exactly the shape the secret-binding rule cannot see.",
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
  // The `withMailSessionOver` variant is covered by the same pattern, being a
  // prefix match -- deliberately, since it opens a session over an already-open
  // stream and N of those is still N conversations against one budget.
  {
    id: "concurrent-session",
    scope: "src/",
    pattern: /\bPromise\.(?:all|allSettled|any|race)\s*\([^;]{0,400}?withMailSession/g,
    why: "A concurrent combinator wrapped around the one mail session orchestrator. Every session is a socket, so a fan-out over N mailboxes opens N of them: production allows six simultaneous connections per Worker invocation (counting KV reads and outbound fetches, one of which the OAuth provider has already spent), and iCloud's own per-account ceiling is lower, undocumented, and deliberately unmeasured because exhausting it locks the user out of their own mail in Mail.app on their own devices. The structural half is the request-scoped gate in src/mail/service.ts, which refuses a second acquire at runtime; this is the detective half, which refuses it at commit time. An account-wide sweep or search must be serial.",
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
      /\bPromise\.(?:all|allSettled|any|race)\s*\([^;]{0,400}?(?:davFetch|createAccount|propfind|fetchCalendars|fetchCalendarObjects|calendarQuery|calendarMultiGet|fetchAddressBooks|fetchVCards|addressBookQuery|addressBookMultiGet|supportedReportSet|createCalendarObject|updateCalendarObject|deleteCalendarObject|withRediscovery|resolveDavAccount|resolveOrganizerAddress|pagedEvents|listCalendars|listEvents|searchEvents|getEvent|listAddressBooks|searchContacts|getContact|runDavDiagnosticOutcome|createEvent|updateEvent|deleteEvent|getEventWithEtag|applyCommit|buildPreview|buildDeletePreview|buildCreatePreview|occurrenceBody|scopelessBody|applyNarrowedDelete|observeDelivery|findFreeSlots|collectFrom)/g,
    why: "A concurrent combinator wrapped around a DAV request, or around one of the service entry points that ends in one. The platform cap is not the reason: workerd queues a seventh simultaneous connection until one of the six receives its response headers, so exhausting that budget costs latency rather than an error. The reason is iCloud's own per-account ceiling, which is lower, undocumented, and deliberately unmeasured -- because exhausting it does not fail politely, it locks the user out of their own mail in Mail.app on their own devices. The entry points are named as well as the library primitives, and the scope is the whole of src/, because that is where a fan-out is actually written: a tool in src/mcp/tools/ never sees a tsdav call, only getEvent or searchContacts, and even a single-calendar listing is already three serial round trips before anything multiplies it -- it was nineteen while an account-wide listing existed, and that form was withdrawn precisely because the sweep could not be repaired by making it concurrent. The WRITE entry points are named alongside the reads, and they are the sharper case: a read that loses the race returns a worse answer and leaves the calendar alone, while a half-completed fan-out over writes leaves a state nobody chose, that no retry can describe, and that cannot be put back. The COMPOSITE tool-layer entry points are named alongside both -- the three preview builders, the commit, the narrowed delete, the occurrence patch and the delivery observation -- because each of them ends in one or more of the names beside it and each was therefore covered only by accident, which is how a guarantee quietly leaves when a body is refactored; they are also, by this rule's own reasoning above, the exact layer a fan-out gets written at. Phase 6 (SCHED-01) adds findFreeSlots and collectFrom: findFreeSlots is the new orchestrator that sweeps every calendar the account has for free/busy time, exactly the account-wide shape D-84 reintroduces, and collectFrom is now called in a loop over collections for the first time -- pagedEvents called it once per request, so it carried no fan-out risk and was correctly absent before, and the temptation to wrap that new loop in a combinator is the precise Pitfall 3 this extension closes. This rule bans CONCURRENCY and not request count -- the two-request serial commit a scoped calendar change deliberately pays is permitted, because a patch needs the whole resource and rebuilding drops every component it did not rebuild. tsdav additionally fans out INSIDE its own fetchCalendars and fetchAddressBooks, in a directory this scanner cannot walk, which is why the structural half of the guarantee is the per-request serialisation gate in src/dav/transport.ts rather than anything visible at a call site; this is the detective half. A multi-collection operation must be serial.",
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
  // your mail". The structural half is that every mailbox is opened read-only,
  // which makes the mutation refusable by the server for a whole session.
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
    why: "A body fetch item written without the peeking form (or its RFC822 synonym, which RFC 3501 makes functionally equivalent). Fetching this way sets the seen flag as a side effect, and the page-listing path touches every message on a page -- so one slip marks a whole page read in a single call, and read status is a field the user relies on. The structural half of the guarantee is that every mailbox is opened read-only, so the server refuses the mutation for the whole session; this rule is the convention half, and it catches the slip before it reaches a server that might not refuse it. Reading the server's reply is unaffected: the response key is spelled without the peek, which is why this rule is anchored on the fetch item list rather than on the spelling alone.",
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
  //      The rule keys on the spelling `userId`, optionally behind one member
  //      access, so `${userId}`, `${actor.userId}` and `${principal.userId}`
  //      are the three live spellings and all three pass;
  //   5. the prefix constant copied into a variable first: `const p =
  //      CONFIRM_KEY_PREFIX;` and then `` `${p}${jti}` ``;
  //   6. the source-IP-keyed counter at `src/auth/login-handler.ts` -- it is
  //      not a constant and not a per-user store. It is audit row S5 and it
  //      belongs to Phase 11, which must not assume this rule covers it;
  //   7. the OAuth library's own keys (`grant:`, `token:`, `client:`), which
  //      live in `node_modules`, outside every entry in `SCAN_ROOTS`.
  //
  // A rule believed to prove more than it does is worse than one whose limits
  // are written down.
  //
  // THE SHAPE. An interpolation whose whole content is an upper-case identifier
  // containing one of eight store words and ending in `PREFIX`, NOT followed by
  // an interpolation of `userId` with at most one member access in front of it.
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
      /\$\{\s*[A-Z0-9_]{0,40}(?:KEY|KV|CACHE|STAGING|CONFIRM|BUCKET|R2|STORE)[A-Z0-9_]{0,40}PREFIX\s*\}(?!\s*\$\{\s*(?:[A-Za-z_][A-Za-z0-9_]{0,40}\s*\.\s*)?userId\s*\})/g,
    why: "A store key built under src/ from a key-prefix constant with no user id straight after it. Every KV and R2 key this project writes belongs to exactly one person -- the staging bucket holds their attachments, the confirm namespace holds their pending writes, the DAV cache holds their account's home URLs. A key with no user segment is a key any signed-in caller can name, so one person's object becomes reachable through another person's request, and nothing fails on the way in: the store returns the object it was asked for. Interpolate the user id straight after the prefix constant, and take it from the signed-in principal -- never from the key, the token or the id being checked, because those are caller-supplied and a caller who chooses the segment chooses whose data to read. If this fired on something that is not a store key, rename the constant so it no longer reads as one. Do not buy it off with a path exclusion: this scanner's skip list is per file and not per rule, so excluding one file here would silently drop the logging, fan-out and write rules on it as well.",
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
 * THE MEMBER ACCESS MATCHES WHAT `MAIL_SECRET_READ` MATCHES (code review
 * WR-03). The two counts were written in the same phase and disagreed for no
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
 * A NOTE FOR PHASE 11 (Phase 9 D-22). This count deliberately does NOT count
 * calls to the props constructor, `principalFromProps`. Nothing calls it until
 * Phase 11, so a count of its callers would fail on zero today, and the only
 * hit under `src/` is its own definition. When the door starts calling it, add
 * an arm for a call to it that is not its own definition (the `function`
 * keyword in front is the difference), so a second caller is seen too.
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
 * A read of one of the two mail secrets off the environment object, permitted
 * in exactly one file of the source tree.
 *
 * THE RULE. Exactly one file under `src/` reads either mail secret off the
 * environment object, and it is `src/principal.ts` — the one constructor that
 * turns the owner's two Worker secrets into a principal. Phase 13 removes the
 * secrets and that constructor together. Until then, everything else that acts
 * for the owner is handed the principal and never sees a secret name.
 *
 * WHY A COUNT RATHER THAN A NEGATIVE. A second reader is a second place a
 * password enters the program without a principal around it, arriving without a
 * decision. Zero is the other failure and the quieter one: it means the owner's
 * constructor was deleted, renamed, or stopped spelling the read this way, and
 * nothing fails on the way out — the tests that covered the deleted code leave
 * with it. "No second reader" is trivially true of a tree with no reader at all.
 *
 * WHY THE LOGIN GATE'S SECRET IS LEFT OUT (Phase 9 D-28). The gate's own secret
 * is not an Apple credential: it gates the authorize form and reaches no
 * account. It has its own single reader in the login gate, and folding it in
 * here would make one count answer two different questions. The pattern names
 * the two mail secrets only, and a row in the test pins the gate's secret as a
 * miss so nobody adds it later by accident.
 *
 * THE MEMBER ACCESS MATCHES WHAT `PROPS_READER` MATCHES (code review WR-03).
 * The two counts were written in the same phase and disagreed for no reason:
 * that one allowed white space around the dot and an optional question mark,
 * this one allowed neither, so the optional-chaining form, the non-null mark
 * and a read broken across two lines by the formatter all fired nothing. Both
 * now allow white space, a new line, an optional question mark and an optional
 * non-null mark on either side of the dot, with the mark owning the white space
 * behind it as one optional group (see `PROPS_READER` for why that grouping is
 * not a style choice). Keep the two identical. A difference between them is a
 * difference nobody decided.
 *
 * WHAT IT DOES NOT SEE. Each of these reads a mail secret and fires nothing:
 *
 *   1. a destructuring of the environment object (`const { APPLE_ID } = env`);
 *   2. an index access with the name as a string (`env["APPLE_ID"]`);
 *   3. an alias of the environment object under another name (`e.APPLE_ID`);
 *   4. a narrow-typed parameter under another name (`secrets.APPLE_ID`);
 *   5. a type cast in parentheses around the environment object, which puts
 *      the cast keyword between the name and the dot.
 *
 * The compiler is the FIRST check for all five (Phase 9 D-14). The three secret
 * names left the shared binding type, so a stray reader does not compile at all,
 * and `test/env-narrowing.test.ts` pins that with expect-error lines. This count
 * is the SECOND check, and it exists because the compiler sees types while this
 * sees text: a cast, a comment or a file the typecheck never reaches gets past
 * one and not the other. Neither sees everything.
 *
 * THE OWNER IS FOUND BY THE SPELLING. The pattern anchors on an identifier
 * named `env`, so the owner's parameter must keep that name. Rename it and this
 * count reports the owner as missing, which is the point: a renamed parameter is
 * how the read would quietly stop being seen.
 *
 * Comments count. In every file under `src/` except the owner, write "the two
 * mail secrets" or "the Apple ID secret" and never the spelled read. A comment
 * that spells it fails the commit hook in the middle of unrelated work. No `g`
 * flag: `scan()` uses `String.prototype.search`, which takes the first match
 * only.
 */
export const MAIL_SECRET_READ =
  /\benv\s*(?:[?!]\s*)?\.\s*(?:APPLE_ID|APPLE_APP_PASSWORD)\b/;

/** The one file under `MAIL_SECRET_READ_SCOPE` permitted to match
 *  `MAIL_SECRET_READ`. */
export const MAIL_SECRET_READ_OWNER = "src/principal.ts";

/** The tree `MAIL_SECRET_READ` is collected from. Tests bind all three secrets
 *  and must be able to spell them, and a test is not a credential path. */
export const MAIL_SECRET_READ_SCOPE = "src/";

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
  "mail-secret-reader-outside-owner",
  "mail-secret-reader-missing",
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
  const mailSecretReaders = [];

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
    if (relativePath.startsWith(MAIL_SECRET_READ_SCOPE)) {
      const mailSecretReadIndex = contents.search(MAIL_SECRET_READ);
      if (mailSecretReadIndex !== -1) {
        mailSecretReaders.push({
          file: relativePath,
          ...positionOf(contents, mailSecretReadIndex),
        });
      }
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
  violations.push(...checkMailSecretReaderOwnership(mailSecretReaders));

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
 * The one reader of the two mail secrets, as a pure function over a list of
 * readers.
 *
 * Same split and same shape as the props count: one owner, both failure
 * directions exercised against a list rather than a fixture tree on disk. See
 * the `MAIL_SECRET_READ` docstring for why this is a count at all, why the
 * login gate's secret is left out, and what it does not see.
 *
 * @param {Array<{file: string, line: number, column: number}>} readers
 */
export function checkMailSecretReaderOwnership(readers) {
  const violations = [];
  for (const reader of readers) {
    if (reader.file === MAIL_SECRET_READ_OWNER) continue;
    violations.push({
      file: reader.file,
      line: reader.line,
      column: reader.column,
      pattern: "mail-secret-reader-outside-owner",
      patternIndex: FORBIDDEN.length + 14,
      why: `A read of one of the two mail secrets off the environment object under ${MAIL_SECRET_READ_SCOPE} outside ${MAIL_SECRET_READ_OWNER}. That file is the one constructor that turns the owner's Worker secrets into a principal, and Phase 13 removes it. A second reader is a second place a password enters the program with no principal around it. Thread the principal to this code instead and read its Apple ID field, or hand it to one of the two password owners. If this fired on a comment, write "the two mail secrets" and not the spelled read. Do not narrow the pattern, do not rename the environment object to hide the read, and do not fold the login gate's secret into this count.`,
    });
  }
  if (readers.length === 0) {
    violations.push({
      file: MAIL_SECRET_READ_OWNER,
      line: 0,
      column: 0,
      pattern: "mail-secret-reader-missing",
      patternIndex: FORBIDDEN.length + 15,
      why: `No file under ${MAIL_SECRET_READ_SCOPE} reads the two mail secrets off the environment object, which means the owner's constructor in ${MAIL_SECRET_READ_OWNER} was deleted, renamed, or rewritten into a form this count cannot see. Nothing fails on the way out when a constructor leaves: the tests that covered it leave with it. Restore the read in that constructor, and keep its parameter named as it is — this count finds its owner by that spelling. If the constructor really moved, that is a change to the safety boundary: get a decision, then change the owner, never the pattern.`,
    });
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
