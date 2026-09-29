// Transfer-encoded windows in, the saved file's bytes out. Pure and socket-free.
//
// The save read fetches a large attachment part as a list of fixed windows, cut
// wherever the window size lands. This module turns that list back into the
// file, one window at a time, without joining the encoded windows into one
// buffer first.
//
// It exists because the shipped decoder, `transferDecode` in `./mime.ts`,
// returns an EMPTY array on malformed base64 by design. That is right for a
// snippet: a bad part yields no preview rather than failing the call. It is
// wrong for a file a person saves. An empty or shortened file that arrives
// under the right name looks like the right file, and nothing on the way to
// the disk would say otherwise. So this module refuses by name instead, and
// never hands back bytes it is not sure of.
//
// No session, no socket, no storage. This module contains no logging calls of
// any kind and must never acquire any.

import { decodeQuotedPrintable } from "./mime";

/**
 * Why a list of windows did not become a file.
 *
 * - `malformed-encoding`: the text is not valid for its declared encoding. A
 *   character outside the base64 alphabet, padding before the end, or a tail
 *   that is not a whole four-character group.
 * - `encoding-unsupported`: the part declared an encoding this module does not
 *   decode. Guessing would produce a file that looks right and is not.
 */
export type DecodeRefusal = "malformed-encoding" | "encoding-unsupported";

/** The file's bytes, or the named reason there are none. Never a short file. */
export type DecodeOutcome =
  | { ok: true; bytes: Uint8Array }
  | { ok: false; refusal: DecodeRefusal };

/**
 * Decode a transfer-encoded part that arrived as a list of windows.
 *
 * `encoding` is the part's declared transfer encoding, matched without regard
 * to case. `base64` and `quoted-printable` are decoded; `7bit`, `8bit` and
 * `binary` are already bytes and are joined as they are. Anything else,
 * including an empty string, is refused.
 *
 * The windows are read, never changed.
 */
export function decodeWindows(
  windows: readonly Uint8Array[],
  encoding: string,
): DecodeOutcome {
  const normalised = encoding.toLowerCase();
  if (normalised === "base64") return decodeBase64Windows(windows);
  if (normalised === "quoted-printable") return decodeQuotedPrintableWindows(windows);
  if (normalised === "7bit" || normalised === "8bit" || normalised === "binary") {
    return { ok: true, bytes: joinWindows(windows) };
  }
  return { ok: false, refusal: "encoding-unsupported" };
}

/** Line breaks and blanks inside base64 text. Skipped, never counted. */
const CR = 0x0d;
const LF = 0x0a;
const SPACE = 0x20;
const TAB = 0x09;

/** The padding character. */
const PAD = 0x3d;

/** Whether each byte value is one of the 64 base64 alphabet characters. */
const IN_ALPHABET: Uint8Array = (() => {
  const table = new Uint8Array(256);
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (let index = 0; index < alphabet.length; index += 1) {
    table[alphabet.charCodeAt(index)] = 1;
  }
  return table;
})();

/** Decodes the ASCII of whole base64 groups into a string `atob` accepts. */
const ASCII = new TextDecoder();

/**
 * Base64, one window at a time.
 *
 * Each window's bytes are walked once. Line breaks, spaces and tabs are
 * skipped. The 64 alphabet characters are kept. `=` is kept only as final
 * padding: in the third or fourth place of the last group, at most two of
 * them, and then nothing but skippable blanks. Anything else is refused.
 *
 * The characters of a group that a window cut in half are carried into the
 * next window, so a cut anywhere (inside a group, between CR and LF, between
 * the two padding characters) changes nothing. A group still unfinished when
 * the windows run out is refused rather than dropped.
 *
 * **One output buffer, sized up front.** Its size is three quarters of the
 * windows' total length, and that can never be too small: every group is four
 * kept characters taken from those windows, and it decodes to at most three
 * bytes. The filled prefix is returned. The encoded windows are never joined,
 * so the peak is the windows the caller already holds, one window-sized
 * scratch copy, and this buffer.
 */
function decodeBase64Windows(windows: readonly Uint8Array[]): DecodeOutcome {
  let total = 0;
  for (const window of windows) total += window.length;

  const out = new Uint8Array(Math.floor((total * 3) / 4));
  let written = 0;

  // The unfinished group carried from the previous window: 0 to 3 characters.
  const carry = new Uint8Array(4);
  let carried = 0;
  // How many padding characters the current group holds.
  let padding = 0;
  // A padded group has closed the text; only blanks may follow.
  let ended = false;

  for (const window of windows) {
    const scratch = new Uint8Array(carried + window.length);
    scratch.set(carry.subarray(0, carried));
    let filled = carried;

    for (let index = 0; index < window.length; index += 1) {
      const byte = window[index] as number;
      if (byte === CR || byte === LF || byte === SPACE || byte === TAB) continue;
      if (ended) return { ok: false, refusal: "malformed-encoding" };

      if (byte === PAD) {
        // Padding belongs only in the third or fourth place of a group.
        if (filled % 4 < 2) return { ok: false, refusal: "malformed-encoding" };
        padding += 1;
        scratch[filled] = byte;
        filled += 1;
        if (filled % 4 === 0) ended = true;
        continue;
      }

      if (IN_ALPHABET[byte] !== 1) return { ok: false, refusal: "malformed-encoding" };
      // A letter after padding inside the same group, as in "QQ=A".
      if (padding > 0) return { ok: false, refusal: "malformed-encoding" };
      scratch[filled] = byte;
      filled += 1;
    }

    const whole = filled - (filled % 4);
    if (whole > 0) {
      let binary: string;
      try {
        binary = atob(ASCII.decode(scratch.subarray(0, whole)));
      } catch {
        // Every group was checked above, so this is not expected. If it
        // happens anyway, the answer is still a refusal and never a short file.
        return { ok: false, refusal: "malformed-encoding" };
      }
      for (let index = 0; index < binary.length; index += 1) {
        out[written] = binary.charCodeAt(index);
        written += 1;
      }
    }

    carried = filled - whole;
    carry.set(scratch.subarray(whole, filled));
  }

  if (carried !== 0) return { ok: false, refusal: "malformed-encoding" };
  return { ok: true, bytes: out.subarray(0, written) };
}

/**
 * An escape a window may have cut short: a bare `=`, `=` and one hex digit, or
 * `=` and a CR whose LF is in the next window.
 */
const UNFINISHED_ESCAPE = /=(?:[0-9A-Fa-f]|\r)?$/;

/**
 * Quoted-printable, one window at a time.
 *
 * Each window is decoded by the shipped decoder, `decodeQuotedPrintable`. An
 * escape the window's end cut short is held back and put in front of the next
 * window, so `=` | CRLF, `=CR` | LF and `=4` | `1` decode exactly as the uncut
 * text does. Whatever is still held back at the end is decoded as it stands,
 * which is also what the uncut text would do with it.
 *
 * The window's bytes become the decoder's text one byte to one character, so
 * any 8-bit byte in the part passes through as itself.
 */
function decodeQuotedPrintableWindows(windows: readonly Uint8Array[]): DecodeOutcome {
  const chunks: Uint8Array[] = [];
  let held = "";

  for (const window of windows) {
    const text = held + byteString(window);
    const unfinished = UNFINISHED_ESCAPE.exec(text);
    const cut = unfinished === null ? text.length : unfinished.index;
    held = text.slice(cut);
    chunks.push(decodeQuotedPrintable(text.slice(0, cut)));
  }
  if (held.length > 0) chunks.push(decodeQuotedPrintable(held));

  return { ok: true, bytes: joinWindows(chunks) };
}

/** Bytes as a string of the same length, one character per byte. */
function byteString(bytes: Uint8Array): string {
  let text = "";
  for (let at = 0; at < bytes.length; at += 0x8000) {
    text += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
  }
  return text;
}

/** Copy a list of byte arrays into one buffer of their total length. */
function joinWindows(windows: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const window of windows) total += window.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const window of windows) {
    out.set(window, at);
    at += window.length;
  }
  return out;
}
