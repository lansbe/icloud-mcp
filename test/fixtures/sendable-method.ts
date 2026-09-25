// The one thing this repository's DAV fetch stubs could not do: tell a method
// this runtime will send from one it refuses to build.
//
// Lifted out of `test/dav-diagnose.test.ts`, where it was written inline for
// one stub, because two more stubs need it and an argument that lives in three
// places is an argument that will be edited in one.

/**
 * Ask the runtime whether this request could exist, before pretending to send it.
 *
 * **A stub that replaces global `fetch` also replaces the runtime's method
 * validation, and that is what made this harness blind.** `vi.stubGlobal("fetch",
 * …)` swaps in a plain function. workerd validates the method string when it
 * builds the `Request`, and it refuses some WebDAV/CalDAV methods outright —
 * including the RFC 4791 calendar-creation method this runtime refuses to build,
 * which `.claude/CLAUDE.md` § 2's role-not-name rule keeps out of every scanned
 * source file. Replacing the global replaces that check too, so a call site
 * using a method this platform cannot express looked green across the whole
 * suite and threw in production — where the throw lands inside
 * `createDavFetch`'s `try`, becomes a `DavConnectError`, and is reported as a
 * transient connection fault against a server that never saw the request.
 *
 * That is not hypothetical. It is what SPIKE-04's first probe run shipped to
 * the owner: `category: connection_failed`, whose safe message read "Could not
 * establish a secure connection to iCloud Mail. This may be transient — safe to
 * retry once." Every clause was false. Nothing was sent, nothing was transient,
 * and retrying could never help. `.planning/PROJECT.md`'s SPIKE-04 row is the
 * authority for the platform constraint.
 *
 * **Constructed and discarded: the construction IS the check.** There is
 * nothing to assert on the built request. A method the runtime refuses throws
 * `TypeError: Invalid HTTP method string` out of the constructor, and a method
 * it accepts returns an object nobody reads.
 *
 * **It catches the whole CLASS, not one name.** A check spelled against a
 * single method would be one assertion and a new blind spot for the next method
 * somebody reaches for. This asks the runtime, so whatever workerd refuses next
 * is refused here too, on the day it is written rather than on the day it
 * deploys.
 *
 * **Call it BEFORE the record push**, on the line above it, in every stub. In
 * production nothing goes on the wire when construction fails, so there would
 * be nothing there to record — a stub that records first and checks second is
 * asserting the existence of a request that never happened.
 *
 * This mirrors `assertSendableMethod` in `src/dav/transport.ts`, which is the
 * production seam every DAV request passes through. The two are deliberately
 * separate: that one maps the failure into this project's error vocabulary,
 * while this one lets the `TypeError` out so a test sees the raw refusal.
 *
 * @param url    The request target, exactly as the stub received it.
 * @param method The method string, exactly as the caller set it.
 */
export function assertMethodIsBuildable(url: string, method: string): void {
  // Constructed and discarded. See the docstring: this is the check.
  new Request(url, { method });
}
