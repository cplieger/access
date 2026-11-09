import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { fixture, index, isObject, validatorFor } from "./test-helpers/wire.js";
import { parseLogActorView, parseLogClassView, parseLogEntryView } from "./wire.js";
import type { Validator } from "./wire.js";

type Path = readonly (string | number)[];

function kind(v: unknown): string {
  if (v === null) {
    return "null";
  }
  return Array.isArray(v) ? "array" : typeof v;
}

// Every value below v with its path: each is a typed wire field or list element, so a value
// of another JSON kind is never the right shape.
function leaves(v: unknown, at: Path = []): { path: Path; value: unknown }[] {
  const below = Array.isArray(v)
    ? v.flatMap((x: unknown, i) => leaves(x, [...at, i]))
    : isObject(v)
      ? Object.entries(v).flatMap(([k, x]) => leaves(x, [...at, k]))
      : [];
  return at.length === 0 ? below : [{ path: at, value: v }, ...below];
}

function strictObjects(v: unknown, at: Path = []): Path[] {
  if (Array.isArray(v)) {
    return v.flatMap((x: unknown, i) => strictObjects(x, [...at, i]));
  }
  if (!isObject(v)) {
    return [];
  }
  return [
    at,
    ...Object.entries(v).flatMap(([k, x]) =>
      k === "public_key" ? [] : strictObjects(x, [...at, k]),
    ),
  ];
}

function replace(root: unknown, path: Path, value: unknown): unknown {
  const copy: unknown = structuredClone(root);
  let parent = copy as Record<string | number, unknown>;
  for (const step of path.slice(0, -1)) {
    parent = parent[step] as Record<string | number, unknown>;
  }
  const last = path[path.length - 1];
  if (last !== undefined) {
    parent[last] = value;
  }
  return copy;
}

function at(root: unknown, path: Path): unknown {
  return path.reduce<unknown>((o, step) => (o as Record<string | number, unknown>)[step], root);
}

// The nested views with no fixture of their own, each fuzzed from its value in its parent's.
const page = fixture("SecurityLogView");
const cases: [string, Validator<unknown>, unknown][] = [
  ...index.map((type): [string, Validator<unknown>, unknown] => [
    type,
    validatorFor(type),
    fixture(type),
  ]),
  ["LogEntryView", parseLogEntryView, at(page, ["entries", 0])],
  ["LogActorView", parseLogActorView, at(page, ["entries", 0, "actor"])],
  ["LogClassView", parseLogClassView, at(page, ["classes", 0])],
];

describe.each(cases)("%s validator", (_type, validate, valid) => {
  it("accepts its fixture, so no property below passes by refusing everything", () => {
    expect(validate(valid)).toEqual(valid);
  });

  it("never throws, and what it accepts it accepts again unchanged", () => {
    fc.assert(
      fc.property(fc.oneof(fc.jsonValue(), fc.constant(valid)), (v) => {
        const out = validate(v);
        if (out !== undefined) {
          expect(validate(out)).toEqual(out);
        }
      }),
    );
  });

  it("refuses the fixture with any value swapped for another JSON kind", () => {
    const sites = leaves(valid);
    fc.assert(
      fc.property(fc.constantFrom(...sites), fc.jsonValue(), (site, value) => {
        fc.pre(kind(value) !== kind(site.value));
        expect(validate(replace(valid, site.path, value))).toBeUndefined();
      }),
    );
  });

  it("refuses the fixture with an unknown key on any wire object", () => {
    const sites = strictObjects(valid);
    const key = fc.string({ minLength: 1 }).filter((k) => k !== "__proto__");
    fc.assert(
      fc.property(fc.constantFrom(...sites), key, fc.jsonValue(), (path, k, value) => {
        const target = at(valid, path);
        fc.pre(isObject(target) && !Object.hasOwn(target, k));
        const v =
          path.length === 0
            ? { ...(valid as object), [k]: value }
            : replace(valid, path, { ...(target as object), [k]: value });
        expect(validate(v)).toBeUndefined();
      }),
    );
  });
});
