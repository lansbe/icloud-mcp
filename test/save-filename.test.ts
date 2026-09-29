// The suggested filename (Phase 29.1, plan 07).
//
// A stranger chose the attachment's filename. The model puts the suggested name
// into a shell command that writes to the person's disk. So the name must keep
// what a person would recognise, and must carry nothing a shell, a file system
// or a reader's eye could be fooled by.
//
// Both directions: names that come through (as themselves, or cleaned), and
// hostile names that must lose their teeth. A property sweep over a few thousand
// random strings holds the output rules for inputs nobody thought of.

import { describe, expect, it } from "vitest";
import { opensAsProgram, suggestSaveName } from "../src/save/filename";

const ENCODER = new TextEncoder();

function utf8Bytes(text: string): number {
  return ENCODER.encode(text).byteLength;
}

/**
 * Every character the output may never hold: path separators, C0 and C1
 * controls, format characters (bidi and zero-width), line and paragraph
 * separators, quotes, the dollar sign, the backtick, and every other shell
 * metacharacter.
 */
const FORBIDDEN = /[/\\\x00-\x1f\x7f-\x9f\p{Cf}\p{Zl}\p{Zp}'"`$;|&<>*?!~#%{}[\]=^]/u;

/** A Windows device name as the whole stem, any case. */
const DEVICE_STEM = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.[^.]*)?$/i;

function assertSafe(output: string): void {
  expect(output.length).toBeGreaterThan(0);
  expect(utf8Bytes(output)).toBeLessThanOrEqual(150);
  expect(output).not.toMatch(FORBIDDEN);
  expect(output.startsWith(".")).toBe(false);
  expect(output.startsWith("-")).toBe(false);
  expect(output).not.toMatch(/[. ]$/);
  expect(output).not.toContain("..");
  expect(output).not.toMatch(DEVICE_STEM);
  expect(output).toBe(output.normalize("NFC"));
}

describe("suggestSaveName: names that come through", () => {
  const rows: [string, string, string][] = [
    ["a plain name", "report.pdf", "report.pdf"],
    ["accents, precomposed", "R\u00e9sum\u00e9 (final).pdf", "R\u00e9sum\u00e9 (final).pdf"],
    ["accents, decomposed, come back composed", "Re\u0301sume\u0301 (final).pdf", "R\u00e9sum\u00e9 (final).pdf"],
    ["a word-processor file", "Offer Letter.docx", "Offer Letter.docx"],
    ["commas, plus and hyphen", "Q3, v2+notes-draft.xlsx", "Q3, v2+notes-draft.xlsx"],
    ["non-Latin letters", "\u5c65\u6b74\u66f8.pdf", "\u5c65\u6b74\u66f8.pdf"],
    ["digits", "2026-09-28.txt", "2026-09-28.txt"],
    ["no extension", "README", "README"],
  ];
  for (const [label, input, expected] of rows) {
    it(`keeps ${label}`, () => {
      expect(suggestSaveName(input)).toBe(expected);
      assertSafe(suggestSaveName(input));
    });
  }
});

describe("suggestSaveName: hostile names lose their teeth", () => {
  const rows: [string, string | null | undefined, string][] = [
    ["a relative path", "../../.ssh/authorized_keys", "authorized_keys"],
    ["a Windows path", "C:\\temp\\x.pdf", "x.pdf"],
    ["a right-to-left override", "a\u202Efdp.exe", "a_fdp.exe"],
    ["a leading dot", ".bashrc", "bashrc"],
    ["only dots", "...", "attachment"],
    ["empty", "", "attachment"],
    ["null", null, "attachment"],
    ["undefined", undefined, "attachment"],
    ["a leading hyphen (an option to curl or mv)", "-rf.pdf", "rf.pdf"],
    ["trailing dots and spaces", "notes.txt. . ", "notes.txt"],
    ["a run of spaces", "a    b.pdf", "a b.pdf"],
    ["a run of underscores", "a____b.pdf", "a_b.pdf"],
    ["a run of dots", "a...b.pdf", "a.b.pdf"],
    ["CON, a device name", "CON.txt", "_CON.txt"],
    ["nul, lower case", "nul", "_nul"],
    ["com1", "com1.pdf", "_com1.pdf"],
    ["LPT9", "LPT9", "_LPT9"],
    ["a device-looking name that is not one", "CONSOLE.txt", "CONSOLE.txt"],
    ["an extension too long", "a.abcdefghijklmnopq", "a.abcdefghijklmnopq"],
  ];
  for (const [label, input, expected] of rows) {
    it(`cleans ${label}`, () => {
      const output = suggestSaveName(input);
      expect(output).toBe(expected);
      assertSafe(output);
    });
  }

  it("keeps no quote, dollar sign, backtick or shell character from any of them", () => {
    const hostile = [
      "$(rm -rf ~).pdf",
      "'quoted'.pdf",
      'a"b',
      "a`id`b.pdf",
      "a;b.pdf",
      "a|b.pdf",
      "a&b.pdf",
      "a<b>c.pdf",
      "a*b.pdf",
      "a?b.pdf",
      "a!b.pdf",
      "${HOME}.pdf",
      "a\nb.pdf",
    ];
    for (const input of hostile) {
      const output = suggestSaveName(input);
      assertSafe(output);
      for (const character of ["'", '"', "`", "$", ";", "|", "&", "<", ">", "*", "?", "!"]) {
        expect(output, `${JSON.stringify(input)} kept ${character}`).not.toContain(character);
      }
    }
    expect(suggestSaveName("$(rm -rf ~).pdf")).toBe("(rm -rf _).pdf");
  });

  it("removes zero-width and other format characters", () => {
    for (const mark of ["\u200B", "\u200C", "\u200D", "\u200E", "\u200F", "\u2066", "\u2069", "\uFEFF", "\u00AD"]) {
      const output = suggestSaveName(`inv${mark}oice.pdf`);
      expect(output).not.toContain(mark);
      assertSafe(output);
    }
  });

  it("never keeps a C0 or C1 control character", () => {
    for (let code = 0; code <= 0x9f; code += 1) {
      if (code > 0x1f && code < 0x7f) continue;
      const output = suggestSaveName(`a${String.fromCharCode(code)}b.pdf`);
      expect(output).not.toContain(String.fromCharCode(code));
      assertSafe(output);
    }
  });

  it("keeps an extension of up to 16 letters or digits, and drops an odd one", () => {
    expect(suggestSaveName("a.pdf")).toBe("a.pdf");
    expect(suggestSaveName("a.docx")).toBe("a.docx");
    expect(suggestSaveName("a.abcdefghijklmnop")).toBe("a.abcdefghijklmnop");
    // Seventeen letters is not an extension. The name keeps the text, but a
    // cap would cut it from the end rather than keep it.
    const long = suggestSaveName(`${"x".repeat(200)}.abcdefghijklmnopq`);
    expect(long.endsWith(".abcdefghijklmnopq")).toBe(false);
    // An extension with a character that is not a letter or digit is not one.
    const odd = suggestSaveName(`${"x".repeat(200)}.p_d`);
    expect(odd.endsWith(".p_d")).toBe(false);
    assertSafe(long);
    assertSafe(odd);
  });

  it("cuts a 300-character name to 150 bytes and keeps the extension", () => {
    const output = suggestSaveName(`${"a".repeat(300)}.pdf`);
    expect(output.endsWith(".pdf")).toBe(true);
    expect(utf8Bytes(output)).toBe(150);
    assertSafe(output);
  });

  it("cuts a multi-byte name on a code-point boundary and keeps the extension", () => {
    // 200 three-byte letters: 600 bytes. The cut must not split one.
    const output = suggestSaveName(`${"\u6587".repeat(200)}.pdf`);
    expect(output.endsWith(".pdf")).toBe(true);
    expect(utf8Bytes(output)).toBeLessThanOrEqual(150);
    expect(utf8Bytes(output)).toBeGreaterThan(145);
    expect(output.replace(".pdf", "")).toMatch(/^\u6587+$/);
    assertSafe(output);
  });

  it("handles a name of 200 emoji: safe, short, and the extension kept", () => {
    const output = suggestSaveName(`${"\u{1F600}".repeat(200)}.pdf`);
    expect(output.endsWith(".pdf")).toBe(true);
    assertSafe(output);
  });

  it("cuts 200 four-byte letters on a code-point boundary", () => {
    // U+20000 is a CJK letter outside the basic plane: four bytes, two UTF-16
    // units. A cut between the two units would leave a lone surrogate.
    const output = suggestSaveName(`${"\u{20000}".repeat(200)}.pdf`);
    expect(output.endsWith(".pdf")).toBe(true);
    expect(utf8Bytes(output)).toBeLessThanOrEqual(150);
    expect(output.replace(".pdf", "")).toMatch(/^(\u{20000})+$/u);
    assertSafe(output);
  });
});

describe("suggestSaveName: a property sweep over random strings", () => {
  it("every output is non-empty, at most 150 bytes, and holds nothing forbidden", () => {
    // A fixed-seed generator, so a failure names the same input every run.
    let seed = 0x29107;
    const next = (): number => {
      seed = (seed * 1103515245 + 12345) >>> 0;
      return seed;
    };
    // Weighted towards the characters that matter: ASCII punctuation, controls,
    // format characters, surrogates, and then anything at all.
    const pick = (): string => {
      const bucket = next() % 6;
      if (bucket === 0) return String.fromCharCode(next() % 0x80);
      if (bucket === 1) return String.fromCharCode(0x80 + (next() % 0x20));
      if (bucket === 2) return String.fromCharCode(0x2000 + (next() % 0x70));
      if (bucket === 3) return String.fromCharCode(0xd800 + (next() % 0x800));
      if (bucket === 4) return ".";
      return String.fromCodePoint(next() % 0x110000);
    };
    for (let round = 0; round < 3000; round += 1) {
      const length = next() % 320;
      let input = "";
      for (let i = 0; i < length; i += 1) input += pick();
      const output = suggestSaveName(input);
      try {
        assertSafe(output);
      } catch (error) {
        throw new Error(`input ${JSON.stringify(input)} gave ${JSON.stringify(output)}`, {
          cause: error,
        });
      }
    }
  });
});

describe("opensAsProgram", () => {
  it("is true for a file that can run code, in any case", () => {
    for (const ext of ["app", "command", "sh", "pkg", "dmg", "exe", "js", "scpt", "bat", "ps1", "jar", "py"]) {
      expect(opensAsProgram(`run.${ext}`), ext).toBe(true);
      expect(opensAsProgram(`run.${ext.toUpperCase()}`), ext.toUpperCase()).toBe(true);
    }
  });

  it("is false for a document, an image and a name with no extension", () => {
    for (const name of ["a.pdf", "a.docx", "a.jpg", "README", "sh", "a.sh.pdf", ""]) {
      expect(opensAsProgram(name), name).toBe(false);
    }
  });
});
