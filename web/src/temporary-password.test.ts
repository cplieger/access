import { describe, expect, it } from "vitest";
import { crc32, looksLikeTemporaryPassword } from "./temporary-password.js";

interface Vector {
  readonly random: string;
  readonly shown: string;
}

// Written by account's TestTemporaryPasswordVectors from the server's generator.
const files = import.meta.glob<{ readonly issued: readonly Vector[] }>(
  "../testdata/temporary-password/vectors.json",
  { eager: true, import: "default" },
);
const issued = Object.values(files)[0]?.issued ?? [];

const SYMBOLS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function undashed(v: Vector): string {
  return v.shown.replaceAll("-", "");
}

function edits(s: string): Record<string, string> {
  const i = 5;
  const c = s.charAt(i);
  const other = SYMBOLS.charAt((SYMBOLS.indexOf(c) + 1) % SYMBOLS.length);
  return {
    substitution: s.slice(0, i) + other + s.slice(i + 1),
    "substitution by U": s.slice(0, i) + "U" + s.slice(i + 1),
    "substitution by ß": s.slice(0, i) + "ß" + s.slice(i + 1),
    swap: s.slice(0, i) + s.charAt(i + 1) + c + s.slice(i + 2),
    omission: s.slice(0, i) + s.slice(i + 1),
    insertion: s.slice(0, i) + "7" + s.slice(i),
  };
}

describe("crc32", () => {
  it("is CRC-32/ISO-HDLC: the catalogue's check value for 123456789 (reveng CRC catalogue)", () => {
    expect(crc32(new TextEncoder().encode("123456789"))).toBe(0xcbf43926);
  });

  it("matches the server's check on every issued value", () => {
    for (const v of issued) {
      const random = Uint8Array.from(v.random.match(/../g) ?? [], (h) => Number.parseInt(h, 16));
      expect(random).toHaveLength(8);
      const check = crc32(random) & 0xffff;
      // The last three symbols carry the check's low 15 bits; the fourth from last its top bit.
      const tail = undashed(v).slice(-4);
      const bits = [...tail].reduce((acc, ch) => acc * 32 + SYMBOLS.indexOf(ch), 0);
      expect(bits & 0xffff, v.shown).toBe(check);
    }
  });
});

describe("looksLikeTemporaryPassword", () => {
  it("reads 64 issued values", () => {
    expect(issued.length).toBeGreaterThanOrEqual(64);
  });

  it("recognises an issued value however it is spelled", () => {
    for (const v of issued) {
      const u = undashed(v);
      const spellings = {
        displayed: v.shown,
        "without separators": u,
        "in lower case": v.shown.toLowerCase(),
        "spaced between letters": [...u].join(" "),
        "O for 0, I and L for 1": u.replaceAll("0", "O").replaceAll("1", "l"),
        "the admin's whole sentence": `Give alice this temporary password: ${v.shown}. It works once, until 14 Nov 18:00.`,
        "in brackets": `[${v.shown}]`,
        "two stray characters before the dashed code": `x7${v.shown}`,
        "two stray characters before the undashed code": `x7${u}`,
        "padded with spaces": `  ${v.shown}\n`,
      };
      for (const [how, value] of Object.entries(spellings)) {
        expect(looksLikeTemporaryPassword(value), `${v.shown} ${how}: ${value}`).toBe(true);
      }
      for (const [edit, value] of Object.entries(edits(u))) {
        expect(looksLikeTemporaryPassword(value), `${v.shown} one ${edit}: ${value}`).toBe(true);
      }
      for (const [edit, value] of Object.entries(edits(v.shown))) {
        expect(looksLikeTemporaryPassword(value), `${v.shown} dashed, one ${edit}: ${value}`).toBe(
          true,
        );
      }
    }
  });

  it.each([
    ["ABCD-EFGH-JKMN-PQRS", "the display form, whose check fails"],
    ["tree bird fish wolf", "the display form"],
    ["elephant fire wind mother", "the display form inside longer words"],
    ["letmeinletmein12", "one edit of a value whose check passes"],
  ])("recognises %j (%s)", (value) => {
    expect(looksLikeTemporaryPassword(value)).toBe(true);
  });

  it.each([
    ["correcthorsebatt"],
    ["my dog is called rex"],
    ["correct horse battery staple"],
    ["abacus tree bird zebra"],
    // A full case mapping (toUpperCase) makes ß "SS" and this one edit from a valid value;
    // the byte-loop fold keeps ß, which Crockford's table does not hold.
    ["ßz7xxa5jcvjrrjy"],
    [""],
  ])("does not recognise %j", (value) => {
    expect(looksLikeTemporaryPassword(value)).toBe(false);
  });

  it("does not recognise an issued value with two omissions in different groups, separators kept", () => {
    for (const v of issued) {
      const g = v.shown.split("-");
      const value = [g[0]?.slice(1), g[1], g[2]?.slice(1), g[3]].join("-");
      expect(looksLikeTemporaryPassword(value), value).toBe(false);
    }
  });
});
