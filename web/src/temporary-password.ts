const SYMBOLS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const LENGTH = 16;

// Four groups of four, look-alikes and lower case included, ASCII only: every letter but U.
const DISPLAY = /[0-9A-TV-Za-tv-z]{4}(?:[- ][0-9A-TV-Za-tv-z]{4}){3}/;

// Web Crypto has no CRC-32, so the client computes its own.
const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  return c;
});

/** CRC-32/ISO-HDLC of bytes, the value of Go's crc32.ChecksumIEEE. */
export function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of bytes) {
    c = (CRC_TABLE[(c ^ b) & 0xff] ?? 0) ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

// The server's normalisation, by code point: a full case mapping (toUpperCase) would make
// "ß" "SS" and "ı" "I", which the server's byte-loop fold does not.
function normalise(value: string): string[] {
  const out: string[] = [];
  for (const ch of value) {
    if (ch === "-" || ch === " ") {
      continue;
    }
    if (ch === "O" || ch === "o") {
      out.push("0");
    } else if (ch === "I" || ch === "i" || ch === "L" || ch === "l") {
      out.push("1");
    } else if (ch >= "a" && ch <= "z") {
      out.push(String.fromCharCode(ch.charCodeAt(0) - 32));
    } else {
      out.push(ch);
    }
  }
  return out;
}

// Whether runes are 16 symbols decoding to eight bytes and the low 16 bits of their CRC-32.
function checks(runes: readonly string[]): boolean {
  if (runes.length !== LENGTH) {
    return false;
  }
  const bytes = new Uint8Array(10);
  let acc = 0;
  let bits = 0;
  let n = 0;
  for (const r of runes) {
    const v = SYMBOLS.indexOf(r);
    if (r.length !== 1 || v < 0) {
      return false;
    }
    acc = ((acc << 5) | v) & 0x1fff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes[n++] = (acc >>> bits) & 0xff;
    }
  }
  const check = ((bytes[8] ?? 0) << 8) | (bytes[9] ?? 0);
  return (crc32(bytes.subarray(0, 8)) & 0xffff) === check;
}

function inWindow(runes: readonly string[]): boolean {
  for (let i = 0; i + LENGTH <= runes.length; i++) {
    if (checks(runes.slice(i, i + LENGTH))) {
      return true;
    }
  }
  return false;
}

function anySymbol(f: (symbol: string) => boolean): boolean {
  for (let i = 0; i < SYMBOLS.length; i++) {
    if (f(SYMBOLS.charAt(i))) {
      return true;
    }
  }
  return false;
}

// One substitution, swap of neighbours, omission or insertion from a value whose check passes.
function oneEdit(runes: readonly string[]): boolean {
  const at = (i: number, insert: readonly string[], drop: number): string[] => [
    ...runes.slice(0, i),
    ...insert,
    ...runes.slice(i + drop),
  ];
  switch (runes.length) {
    case LENGTH:
      for (let i = 0; i < LENGTH; i++) {
        if (anySymbol((s) => checks(at(i, [s], 1)))) {
          return true;
        }
      }
      for (let i = 0; i + 1 < LENGTH; i++) {
        if (checks(at(i, [runes[i + 1] ?? "", runes[i] ?? ""], 2))) {
          return true;
        }
      }
      return false;
    case LENGTH - 1:
      for (let i = 0; i < LENGTH; i++) {
        if (anySymbol((s) => checks(at(i, [s], 0)))) {
          return true;
        }
      }
      return false;
    case LENGTH + 1:
      return runes.some((_, i) => checks(at(i, [], 1)));
    default:
      return false;
  }
}

/**
 * Whether value looks like a temporary password: the display form anywhere in it, a run of 16
 * symbols whose check passes, or the whole value within one edit of one. A plain sign-in screen
 * whose state has temporary_password_https_only checks it before loginPassword and, when it is
 * true, sends nothing and points to the HTTPS address. It reads no store and sends no request.
 */
export function looksLikeTemporaryPassword(value: string): boolean {
  const trimmed = value.trim();
  if (DISPLAY.test(trimmed)) {
    return true;
  }
  const runes = normalise(trimmed);
  return inWindow(runes) || oneEdit(runes);
}
