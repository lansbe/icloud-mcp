// The suggested filename for a saved attachment (Phase 29.1).
//
// A stranger chose the attachment's filename. The model puts the suggested name
// into a shell command that writes to the person's own disk. So the name keeps
// what a person would recognise, including accents and non-Latin letters, and
// carries nothing else: no path separator, no leading dot or hyphen, no control,
// bidi or zero-width character, no quote, dollar sign, backtick or other shell
// character, and no Windows device name. It is at most 150 UTF-8 bytes, which
// leaves room for " (999)" and ".part" under the 255-byte name limit.
//
// WHY NOT THE STAGING KEY SANITISER. `../staging/r2.ts` has its own sanitiser,
// for storage keys. It keeps only ASCII letters and digits, so "Résumé" would
// come out as "R-sum-". A key needs that. A name on a person's disk does not.
//
// STILL A STRANGER'S TEXT. The output is derived from what a stranger wrote, so
// it travels only inside the untrusted fence, never in the trusted half.
//
// This module contains no logging calls of any kind and must never acquire any.

/** The name when nothing usable is left. */
const FALLBACK = "attachment";

/** The most UTF-8 bytes a suggested name may take. */
export const MAX_SAVE_NAME_BYTES = 150;

/** One character that may stay: a letter, a mark, a number, or a safe sign. */
const ALLOWED = /^[\p{L}\p{M}\p{N} ._\-(),+]$/u;

/** An extension: 1 to 16 letters or digits. */
const EXTENSION = /^[\p{L}\p{N}]{1,16}$/u;

/** A Windows device name, any case. */
const DEVICE_NAME = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;

/** Extensions of files that can run code when opened. */
const PROGRAM_EXTENSIONS = new Set([
  "app",
  "command",
  "sh",
  "pkg",
  "dmg",
  "exe",
  "js",
  "scpt",
  "bat",
  "ps1",
  "jar",
  "py",
]);

const ENCODER = new TextEncoder();

function utf8Length(text: string): number {
  return ENCODER.encode(text).byteLength;
}

/** Cut `text` to at most `budget` UTF-8 bytes, only between code points. */
function cutToBytes(text: string, budget: number): string {
  let out = "";
  let used = 0;
  for (const character of text) {
    const size = utf8Length(character);
    if (used + size > budget) break;
    out += character;
    used += size;
  }
  return out;
}

/**
 * A safe, readable filename for a saved attachment, from the name a stranger
 * gave it. Never empty. The steps run in order:
 *
 * 1. no string, or an empty one: `attachment`;
 * 2. Unicode NFC, so an accent has one spelling;
 * 3. only the part after the last `/` or `\`;
 * 4. letters, marks, numbers, space and `._-(),+` stay; anything else becomes
 *    `_`;
 * 5. runs of `_`, spaces and dots collapse; trailing dots and spaces go;
 * 6. an extension of 1 to 16 letters or digits after the last dot is kept
 *    (a dot at the very start is not an extension's); the stem loses leading
 *    dots, spaces, underscores and hyphens, and trailing dots and spaces;
 * 7. the stem is cut, between code points, so the whole name fits 150 bytes;
 * 8. a Windows device name gets a leading `_`;
 * 9. an empty stem becomes `attachment`.
 */
export function suggestSaveName(original: unknown): string {
  if (typeof original !== "string" || original.length === 0) return FALLBACK;

  const composed = original.normalize("NFC");
  const lastSeparator = Math.max(composed.lastIndexOf("/"), composed.lastIndexOf("\\"));
  const base = composed.slice(lastSeparator + 1);

  let cleaned = "";
  for (const character of base) cleaned += ALLOWED.test(character) ? character : "_";
  cleaned = cleaned
    .replace(/_+/g, "_")
    .replace(/ +/g, " ")
    .replace(/\.+/g, ".")
    .replace(/[. ]+$/, "");

  let stem = cleaned;
  let extension = "";
  const dot = cleaned.lastIndexOf(".");
  if (dot > 0 && EXTENSION.test(cleaned.slice(dot + 1))) {
    stem = cleaned.slice(0, dot);
    extension = cleaned.slice(dot + 1);
  }
  const suffix = extension === "" ? "" : `.${extension}`;

  stem = stem.replace(/^[. _-]+/, "").replace(/[. ]+$/, "");
  stem = cutToBytes(stem, MAX_SAVE_NAME_BYTES - utf8Length(suffix)).replace(/[. ]+$/, "");

  // Windows reads the part before the first dot as the device name.
  if (DEVICE_NAME.test(stem.split(".")[0] ?? "")) stem = `_${stem}`;
  if (stem === "") stem = FALLBACK;

  return `${stem}${suffix}`;
}

/**
 * Whether a file with this name can run code when the person opens it.
 *
 * Read from the suggested name's extension, against a fixed list. A warning,
 * never a refusal: the owner allowed any type to be saved.
 */
export function opensAsProgram(name: string): boolean {
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return false;
  return PROGRAM_EXTENSIONS.has(name.slice(dot + 1).toLowerCase());
}
