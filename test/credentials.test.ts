// The write-only credential helper.
//
// Every assertion here is on the BYTES WRITTEN TO A FAKE WRITER, never on a
// returned string — a function that returned the command line is exactly what
// this design forbids, because IMAP puts the app-specific password inline in
// that line and an object holding it can be logged, serialized, attached to an
// error, or spread into a response.

import { describe, expect, it } from "vitest";
import type { Env } from "../src/env";
import { ImapAuthError } from "../src/errors";
import * as credentials from "../src/mail/credentials";
import {
  draftFromAddress,
  writeAuthenticatePlainCommand,
  writeLoginCommand,
} from "../src/mail/credentials";
import { createFakeDuplex } from "./fixtures/fake-duplex";

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

/**
 * A binding surface carrying only what the helper reads.
 *
 * Both parameters admit `undefined` because a Workers Secret binding does: an
 * unset, deleted, or failed-to-provision Secret arrives absent, and the
 * unprovisioned case is one this file has to be able to express.
 */
function fakeEnv(
  appleId: string | undefined,
  password: string | undefined,
): Env {
  return {
    APPLE_ID: appleId,
    APPLE_APP_PASSWORD: password,
  } as unknown as Env;
}

/** Run one helper against a recording writer and hand back what it wrote. */
async function capture(
  write: (
    writer: WritableStreamDefaultWriter<Uint8Array>,
  ) => Promise<void>,
): Promise<{ bytes: Uint8Array; text: string; returned: unknown }> {
  const duplex = createFakeDuplex([]);
  const writer = duplex.writable.getWriter();
  const returned = await write(writer);
  writer.releaseLock();

  expect(duplex.writes).toHaveLength(1);
  const bytes = duplex.writes[0];
  return { bytes, text: DECODER.decode(bytes), returned };
}

/**
 * Run one helper against a recording writer, expecting it to refuse outright.
 *
 * A sibling of `capture` rather than a reuse of it: `capture` asserts exactly
 * one write happened, and the whole point here is that none did. A refusal
 * raised *after* a partial write would have already put the injected line on
 * the wire, so the zero-write assertion is the one that carries the security
 * property — the rejection type alone would pass against a helper that wrote
 * first and complained afterwards.
 */
async function expectRefusal(
  write: (
    writer: WritableStreamDefaultWriter<Uint8Array>,
  ) => Promise<void>,
): Promise<void> {
  const duplex = createFakeDuplex([]);
  const writer = duplex.writable.getWriter();

  await expect(write(writer)).rejects.toBeInstanceOf(ImapAuthError);

  writer.releaseLock();
  expect(duplex.writes).toHaveLength(0);
  expect(duplex.writtenLines()).toEqual([]);
}

/** Decode a base64 blob back to the exact bytes it was built from. */
function fromBase64(blob: string): Uint8Array {
  const binary = atob(blob);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

describe("module shape", () => {
  it("exports the two write functions and the one identity reader, nothing else", () => {
    // The design constraint made checkable: there is no accessor that returns
    // the PASSWORD, not even a thunk that would produce one. The third export
    // returns the Apple ID and is the one deliberate exception to "returns
    // nothing" — a distinction the module header states rather than leaves to
    // be inferred, because a reader meeting it cold would read it as a breach.
    expect(Object.keys(credentials).sort()).toEqual([
      "draftFromAddress",
      "writeAuthenticatePlainCommand",
      "writeLoginCommand",
    ]);
  });

  it("exports only functions", () => {
    for (const value of Object.values(credentials)) {
      expect(typeof value).toBe("function");
    }
  });
});

describe("writeLoginCommand", () => {
  it("writes a tagged LOGIN with both arguments as IMAP quoted strings", async () => {
    const { text } = await capture((writer) =>
      writeLoginCommand(writer, "a2", fakeEnv("someone@icloud.com", "abcd-efgh")),
    );

    expect(text).toBe('a2 LOGIN "someone@icloud.com" "abcd-efgh"\r\n');
  });

  it("escapes an embedded quote and an embedded backslash", async () => {
    // Unescaped, either character desynchronises the server's parser and the
    // failure looks exactly like a rejected credential.
    const { text } = await capture((writer) =>
      writeLoginCommand(
        writer,
        "a2",
        fakeEnv('who"ami', 'pa"ss\\word'),
      ),
    );

    expect(text).toBe('a2 LOGIN "who\\"ami" "pa\\"ss\\\\word"\r\n');
  });

  it("terminates the line with CRLF, not a bare newline", async () => {
    const { text } = await capture((writer) =>
      writeLoginCommand(writer, "a2", fakeEnv("a@b.c", "pw")),
    );

    expect(text.endsWith("\r\n")).toBe(true);
    expect(text.slice(0, -2)).not.toContain("\n");
  });

  it("returns undefined — nothing credential-bearing comes back", async () => {
    const { returned } = await capture((writer) =>
      writeLoginCommand(writer, "a2", fakeEnv("a@b.c", "sekrit")),
    );

    expect(returned).toBeUndefined();
  });

  it("measures the wire in UTF-8 bytes, not JavaScript code units", async () => {
    // The two diverge on any multi-byte character. Nothing in this phase sends
    // a counted literal, but this is the seam a later phase's APPEND lengths
    // inherit, and getting it wrong there fails silently on exactly the
    // messages a user cares about.
    const password = "pässwörd–🔑";
    const { bytes, text } = await capture((writer) =>
      writeLoginCommand(writer, "a2", fakeEnv("a@b.c", password)),
    );

    expect(bytes.byteLength).toBe(ENCODER.encode(text).byteLength);
    expect(bytes.byteLength).toBeGreaterThan(text.length);
    expect(text).toContain(password);
  });
});

describe("writeAuthenticatePlainCommand", () => {
  it("writes a tagged AUTHENTICATE PLAIN carrying the initial response inline", async () => {
    const { text } = await capture((writer) =>
      writeAuthenticatePlainCommand(
        writer,
        "a3",
        fakeEnv("someone@icloud.com", "abcd-efgh"),
      ),
    );

    const match = /^a3 AUTHENTICATE PLAIN (\S+)\r\n$/.exec(text);
    expect(match).not.toBeNull();
  });

  it("builds the blob as base64 over the NUL-delimited UTF-8 bytes", async () => {
    const appleId = "someone@icloud.com";
    const password = "abcd-efgh";
    const { text } = await capture((writer) =>
      writeAuthenticatePlainCommand(writer, "a3", fakeEnv(appleId, password)),
    );

    const blob = text.slice("a3 AUTHENTICATE PLAIN ".length, -2);
    const decoded = fromBase64(blob);

    expect(decoded).toEqual(ENCODER.encode(`\0${appleId}\0${password}`));
    expect(decoded[0]).toBe(0);
    expect(decoded[1 + appleId.length]).toBe(0);
  });

  it("base64s the UTF-8 bytes, not the UTF-16 code units", async () => {
    // Encoding to bytes first and base64-ing those is the only correct order.
    // Handing a JavaScript string straight to the base64 primitive is the same
    // class of bug as measuring a literal length in code units.
    const appleId = "sömeone@icloud.com";
    const password = "pässwörd–🔑";
    const { text } = await capture((writer) =>
      writeAuthenticatePlainCommand(writer, "a3", fakeEnv(appleId, password)),
    );

    const blob = text.slice("a3 AUTHENTICATE PLAIN ".length, -2);
    const decoded = fromBase64(blob);
    const expected = ENCODER.encode(`\0${appleId}\0${password}`);

    expect(decoded).toEqual(expected);
    // The whole point: more bytes than characters.
    expect(decoded.byteLength).toBeGreaterThan(
      1 + appleId.length + 1 + password.length,
    );
    expect(DECODER.decode(decoded.subarray(1 + expected.indexOf(0, 1)))).toBe(
      password,
    );
  });

  it("emits only base64 alphabet characters, so the credential is not readable inline", async () => {
    const password = "abcd-efgh";
    const { text } = await capture((writer) =>
      writeAuthenticatePlainCommand(writer, "a3", fakeEnv("a@b.c", password)),
    );

    const blob = text.slice("a3 AUTHENTICATE PLAIN ".length, -2);
    expect(blob).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(blob).not.toContain(password);
  });

  it("returns undefined — nothing credential-bearing comes back", async () => {
    const { returned } = await capture((writer) =>
      writeAuthenticatePlainCommand(writer, "a3", fakeEnv("a@b.c", "sekrit")),
    );

    expect(returned).toBeUndefined();
  });

  it("measures the wire in UTF-8 bytes, not JavaScript code units", async () => {
    const { bytes, text } = await capture((writer) =>
      writeAuthenticatePlainCommand(
        writer,
        "a3",
        fakeEnv("a@b.c", "pässwörd–🔑"),
      ),
    );

    expect(bytes.byteLength).toBe(ENCODER.encode(text).byteLength);
  });
});

/** Both write helpers, each reduced to "here is an env, write the command". */
const HELPERS: [
  string,
  (writer: WritableStreamDefaultWriter<Uint8Array>, env: Env) => Promise<void>,
][] = [
  ["writeLoginCommand", (writer, env) => writeLoginCommand(writer, "a2", env)],
  [
    "writeAuthenticatePlainCommand",
    (writer, env) => writeAuthenticatePlainCommand(writer, "a3", env),
  ],
];

/** Which of the two bindings carries the bad value in a given case. */
const FIELDS: [string, (bad: string | undefined) => Env][] = [
  ["APPLE_ID", (bad) => fakeEnv(bad, "abcd-efgh")],
  ["APPLE_APP_PASSWORD", (bad) => fakeEnv("someone@icloud.com", bad)],
];

/**
 * Values carrying a character that is illegal inside an IMAP quoted string.
 *
 * RFC 3501's QUOTED-CHAR production excludes CR and LF outright — they are not
 * escapable, so a value carrying one does not produce a malformed argument, it
 * terminates the command line early and injects a second line whose tag comes
 * from credential bytes. NUL is excluded for the same reason and additionally
 * delimits the SASL PLAIN blob.
 *
 * The trailing-newline case is the one that actually happens: provisioning a
 * secret from a file leaves the file's final newline on the value.
 */
const ILLEGAL_VALUES: [string, string][] = [
  ["a trailing line feed", "abcd-efgh\n"],
  ["a trailing carriage return", "abcd-efgh\r"],
  ["a NUL", "abcd\0efgh"],
  ["a mid-value line break", "abcd\r\nz9 LOGOUT\r\nefgh"],
];

/** The two shapes an unprovisioned Workers Secret binding takes at runtime. */
const UNPROVISIONED_VALUES: [string, string | undefined][] = [
  ["absent", undefined],
  ["empty", ""],
];

describe("refuses illegal credential bytes before writing anything", () => {
  for (const [helperName, invoke] of HELPERS) {
    for (const [fieldName, buildEnv] of FIELDS) {
      for (const [label, value] of ILLEGAL_VALUES) {
        it(`${helperName}: ${fieldName} with ${label}`, async () => {
          await expectRefusal((writer) => invoke(writer, buildEnv(value)));
        });
      }
    }
  }

  it("refuses rather than escaping — no encoding of CR or LF is attempted", async () => {
    // The distinction matters: an escape would be silently wrong, because the
    // RFC gives these characters no escaped form. Whatever a caller meant by a
    // value containing one, it is not something this module can send.
    await expectRefusal((writer) =>
      writeLoginCommand(writer, "a2", fakeEnv("a@b.c", 'pass\\"\r\nword')),
    );
  });

  it("carries no fragment of either value in what it raises", async () => {
    const appleId = "leaky-apple-id@icloud.com";
    const password = "leaky-password-value";
    const duplex = createFakeDuplex([]);
    const writer = duplex.writable.getWriter();

    const raised = await writeLoginCommand(
      writer,
      "a2",
      fakeEnv(appleId, `${password}\n`),
    ).then(
      () => null,
      (err: unknown) => err,
    );
    writer.releaseLock();

    expect(raised).toBeInstanceOf(ImapAuthError);
    const serialized = JSON.stringify({
      message: (raised as Error).message,
      stack: (raised as Error).stack,
      own: Object.getOwnPropertyNames(raised as object),
    });
    expect(serialized).not.toContain(password);
    expect(serialized).not.toContain(appleId);
    // Nor a length, which would be an oracle in its own right.
    expect((raised as Error).message).toBe("imap-credentials-rejected");
  });
});

describe("refuses an unprovisioned binding before writing anything", () => {
  // Today the login helper throws a TypeError here, which withWriter converts
  // to ImapConnectError and toErrorCategory reports as connection_failed —
  // whose safe message says a retry is worth trying. A secret that was never
  // set is not something a retry fixes, and retrying in a loop is the fastest
  // way to reach iCloud's connection ceiling.
  for (const [helperName, invoke] of HELPERS) {
    for (const [fieldName, buildEnv] of FIELDS) {
      for (const [label, value] of UNPROVISIONED_VALUES) {
        it(`${helperName}: ${fieldName} ${label}`, async () => {
          await expectRefusal((writer) => invoke(writer, buildEnv(value)));
        });
      }
    }
  }

  it("refuses when both bindings are absent", async () => {
    await expectRefusal((writer) =>
      writeLoginCommand(writer, "a2", fakeEnv(undefined, undefined)),
    );
  });

  // The SASL path's presence check is behavioural, not compiler-driven: its
  // values reach a template literal, which stringifies an absent binding to the
  // six characters "undefined" without complaint. A green typecheck is not
  // evidence the check is redundant — without it, this helper base64s a literal
  // placeholder username and password and sends them to iCloud.
  it("writeAuthenticatePlainCommand does not base64 a stringified absent binding", async () => {
    await expectRefusal((writer) =>
      writeAuthenticatePlainCommand(
        writer,
        "a3",
        fakeEnv(undefined, undefined),
      ),
    );
  });
});

// The invariant `src/mcp/tools/diagnose.ts` and `src/mail/diagnose.ts` both
// depend on, stated here as a check rather than left as prose in two places.
//
// Both files argue `authFailureDetail` is safe to forward because the
// credential travels in the command sent and never in the reply. That argument
// holds only while the credential cannot influence what the server says — and a
// value that terminated the command line early would inject a second line whose
// tag came from credential bytes, which the server then quotes back. One line
// written means one line the server can answer.
//
// Read the argument in those two files; this block does not restate it. A
// Phase 2 or Phase 4 author who widens `quoted` to handle some new case by
// escaping rather than refusing will trip this.
describe("a written command is exactly one line", () => {
  /** Awkward but entirely legal values — none may be refused. */
  const ACCEPTED_VALUES: [string, string][] = [
    ["an embedded quote", 'pa"ssword'],
    ["an embedded backslash", "pa\\ssword"],
    ["multi-byte characters", "pässwörd–🔑"],
    ["a space", "correct horse battery staple"],
    ["a long value", "z".repeat(2048)],
    ["every escapable character at once", 'a"b\\c"d\\'],
  ];

  for (const [label, password] of ACCEPTED_VALUES) {
    it(`writeLoginCommand writes one terminated line: ${label}`, async () => {
      const { bytes } = await capture((writer) =>
        writeLoginCommand(writer, "a2", fakeEnv("someone@icloud.com", password)),
      );

      const lineFeeds = [...bytes].filter((byte) => byte === 0x0a);
      expect(lineFeeds).toHaveLength(1);
      expect(bytes[bytes.length - 1]).toBe(0x0a);
      // And it is a CRLF pair, not a bare line feed that happens to be last.
      expect(bytes[bytes.length - 2]).toBe(0x0d);
      expect([...bytes].filter((byte) => byte === 0x0d)).toHaveLength(1);
    });

    it(`writeAuthenticatePlainCommand writes one terminated line: ${label}`, async () => {
      const { bytes } = await capture((writer) =>
        writeAuthenticatePlainCommand(
          writer,
          "a3",
          fakeEnv("someone@icloud.com", password),
        ),
      );

      expect([...bytes].filter((byte) => byte === 0x0a)).toHaveLength(1);
      expect(bytes[bytes.length - 1]).toBe(0x0a);
      expect(bytes[bytes.length - 2]).toBe(0x0d);
    });
  }

  it("holds when the Apple ID carries the awkward characters too", async () => {
    const { bytes } = await capture((writer) =>
      writeLoginCommand(writer, "a2", fakeEnv('who"a\\mi', "abcd-efgh")),
    );

    expect([...bytes].filter((byte) => byte === 0x0a)).toHaveLength(1);
    expect(bytes[bytes.length - 1]).toBe(0x0a);
  });
});

// ---------------------------------------------------------------------------
// The authoring identity (DRAFT-02)
// ---------------------------------------------------------------------------

describe("draftFromAddress", () => {
  it("returns the Apple ID and nothing else", () => {
    // A bare string, not an object holding one: there is nothing here to spread
    // into a response, attach to an error, or serialize by accident.
    const returned = draftFromAddress(
      fakeEnv("someone@icloud.com", "abcd-efgh"),
    );

    expect(returned).toBe("someone@icloud.com");
    expect(typeof returned).toBe("string");
  });

  it("never reads the app-specific password", () => {
    // The password is absent from the binding surface entirely and the call
    // still succeeds, which is the discriminating form: an implementation that
    // touched it would refuse here.
    expect(
      draftFromAddress({ APPLE_ID: "someone@icloud.com" } as unknown as Env),
    ).toBe("someone@icloud.com");
  });

  for (const [label, value] of UNPROVISIONED_VALUES) {
    it(`refuses an unprovisioned binding rather than authoring as a placeholder: ${label}`, () => {
      // BEHAVIOURAL, not compiler-driven. The value lands in a template literal
      // one module over, and a template literal accepts an absent binding
      // silently — stringifying it to the nine characters that spell the absent
      // value. Without this check a draft goes out with a fabricated sender and
      // the typecheck says nothing.
      expect(() =>
        draftFromAddress(fakeEnv(value, "abcd-efgh")),
      ).toThrow(ImapAuthError);
    });
  }

  it("does not return a string containing the placeholder spelling", () => {
    // Stated as a containment assertion as well as a refusal, because the
    // failure this guards is not "an exception was not thrown" — it is a value
    // that looks like an address and is not one.
    let returned: string | null = null;
    try {
      returned = draftFromAddress(fakeEnv(undefined, "abcd-efgh"));
    } catch {
      returned = null;
    }

    expect(returned).toBeNull();
  });

  it("refuses an Apple ID carrying CR or LF rather than repairing it", () => {
    // The value reaches a header line. The ordinary way a secret acquires one
    // of these is mundane and is why this is not theoretical: a secret
    // provisioned from a file carries the file's trailing newline, and a
    // newline in that header injects a second header.
    for (const bad of [
      "someone@icloud.com\r\n",
      "someone@icloud.com\nBcc: attacker@evil.invalid",
    ]) {
      expect(() => draftFromAddress(fakeEnv(bad, "abcd-efgh"))).toThrow(
        ImapAuthError,
      );
    }
  });
});
