import { describe, expect, it } from "vitest";

import {
  ARM_BUILD_ATTRIBUTE_TAGS,
  ARM_CPU_ARCH_PROFILE_M,
  ARM_ELF_FLOAT_ABIS,
  ARM_ELF_M_PROFILE_ARCHITECTURES,
  armElfFloatAbi,
  armElfMProfile,
  parseArmBuildAttributes,
  type ArmBuildAttributes,
} from "./armBuildAttributes.js";
import { ok } from "./result.js";
import { ARCHITECTURE_VARIANT_NAMES } from "./architectureVariant.js";

const declared = (
  cpuArch: number | null,
  cpuArchProfile: number | null,
): ArmBuildAttributes => ({ cpuArch, cpuArchProfile, vfpArgs: null });

const A = 0x41;
const R = 0x52;
const M = ARM_CPU_ARCH_PROFILE_M;
const S = 0x53;

describe("ARM build attribute vocabulary", () => {
  it("reads the AEABI tag numbers it names", () => {
    // Persisted profiles record the values of these tags, so the numbers are pinned.
    expect(ARM_BUILD_ATTRIBUTE_TAGS).toEqual({
      cpuArch: 6,
      cpuArchProfile: 7,
      vfpArgs: 28,
    });
    expect(ARM_CPU_ARCH_PROFILE_M).toBe("M".charCodeAt(0));
  });

  it("reaches every variant from at least one architecture", () => {
    expect(
      [
        ...new Set(
          ARM_ELF_M_PROFILE_ARCHITECTURES.map(({ variant }) => variant),
        ),
      ].sort(),
    ).toEqual([...ARCHITECTURE_VARIANT_NAMES].sort());
  });
});

describe.each(ARM_ELF_M_PROFILE_ARCHITECTURES)(
  "Tag_CPU_arch $cpuArch ($label)",
  (row) => {
    it("maps with the M profile", () => {
      expect(armElfMProfile(declared(row.cpuArch, M))).toEqual({
        kind: "m-profile",
        variant: row.variant,
        architecture: row,
      });
    });

    it.each([A, R, S, 0])("does not map with profile %i", (profile) => {
      const outcome = armElfMProfile(declared(row.cpuArch, profile));
      if ("requiresMProfile" in row)
        expect(outcome).toEqual({ kind: "other-profile" });
      else expect(outcome).toMatchObject({ kind: "unknown" });
    });

    it("needs the profile only where the architecture spans profiles", () => {
      const outcome = armElfMProfile(declared(row.cpuArch, null));
      if ("requiresMProfile" in row)
        expect(outcome).toMatchObject({ kind: "unknown" });
      else
        expect(outcome).toEqual({
          kind: "m-profile",
          variant: row.variant,
          architecture: row,
        });
    });
  },
);

describe("declarations outside the table", () => {
  it.each([
    ["ARMv7-A", 10, A],
    ["ARMv7-R", 10, R],
    ["ARMv7 A or R", 10, S],
    ["ARMv8-A", 14, A],
    ["ARMv8-R", 15, R],
    ["ARMv5TE without a profile", 4, null],
    ["ARMv6K with profile 0", 9, 0],
  ] as const)("%s is another profile", (_name, cpuArch, profile) => {
    expect(armElfMProfile(declared(cpuArch, profile))).toEqual({
      kind: "other-profile",
    });
  });

  it.each([
    [
      "an unmapped M architecture",
      declared(99, M),
      "Tag_CPU_arch 99 with profile M has no M-profile variant",
    ],
    [
      "the M profile without an architecture",
      declared(null, M),
      "Tag_CPU_arch_profile declares M without Tag_CPU_arch",
    ],
    [
      "no declaration",
      declared(null, null),
      "the attributes declare neither Tag_CPU_arch nor Tag_CPU_arch_profile",
    ],
    [
      "a contradiction",
      declared(13, A),
      "ARMv7E-M (Tag_CPU_arch 13) contradicts profile A",
    ],
  ])("%s stays unknown", (_name, attributes, reason) => {
    expect(armElfMProfile(attributes)).toEqual({ kind: "unknown", reason });
  });

  it("leaves another profile without an architecture outside the M profile", () => {
    expect(armElfMProfile(declared(null, A))).toEqual({
      kind: "other-profile",
    });
  });
});

describe("float ABI reading", () => {
  const SOFT = 0x05000200;
  const HARD = 0x05000400;
  const NONE = 0x05000000;

  it.each([
    [HARD, null, "vfp"],
    [HARD, 1, "vfp"],
    [HARD, 3, "vfp"],
    [HARD, 0, "unresolved"],
    [HARD, 2, "unresolved"],
    [SOFT, null, "base"],
    [SOFT, 0, "base"],
    [SOFT, 3, "base"],
    [SOFT, 1, "unresolved"],
    [SOFT | HARD, null, "unresolved"],
    [NONE, null, "undeclared"],
    [NONE, 0, "base"],
    [NONE, 1, "vfp"],
    [NONE, 2, "toolchain"],
    [NONE, 3, "compatible"],
    [NONE, 4, "unresolved"],
    // The float flags exist only in EABI version 5 headers.
    [0x04000400, null, "undeclared"],
    [0x00000200, 1, "vfp"],
  ] as const)(
    "flags %i with Tag_ABI_VFP_args %s read %s",
    (flags, vfpArgs, abi) => {
      expect(armElfFloatAbi(flags, vfpArgs)).toBe(abi);
      expect(ARM_ELF_FLOAT_ABIS).toContain(abi);
    },
  );
});

const uleb = (value: number): number[] => {
  const bytes: number[] = [];
  let rest = value;
  do {
    const low = rest % 0x80;
    rest = Math.floor(rest / 0x80);
    bytes.push(rest === 0 ? low : low | 0x80);
  } while (rest !== 0);
  return bytes;
};
const u32 = (value: number, little: boolean): number[] => {
  const bytes = Buffer.alloc(4);
  if (little) bytes.writeUInt32LE(value);
  else bytes.writeUInt32BE(value);
  return [...bytes];
};
const text = (value: string): number[] => [...Buffer.from(value, "latin1"), 0];
const scope = (tag: number, body: number[], little = true): number[] => [
  ...uleb(tag),
  ...u32(uleb(tag).length + 4 + body.length, little),
  ...body,
];
const subsection = (vendor: string, data: number[], little = true) => [
  ...u32(4 + vendor.length + 1 + data.length, little),
  ...text(vendor),
  ...data,
];
const section = (...subsections: number[][]): Buffer =>
  Buffer.from([0x41, ...subsections.flat()]);
const file = (attributes: number[], little = true) =>
  section(subsection("aeabi", scope(1, attributes, little), little));
const parse = (bytes: Buffer, little = true) =>
  parseArmBuildAttributes(bytes, little);

describe("ARM build attribute section", () => {
  // .ARM.attributes written by Clang and LLD 19.1.7 for the named targets.
  const CLANG = {
    "thumbv6m soft-float": [
      "4140000000616561626900013600000043322e30390005636f727465782d6d3000060c074d080009010e0011011204140115001703180119011a021e0122002601",
      { cpuArch: 12, cpuArchProfile: 0x4d, vfpArgs: null },
    ],
    "thumbv7em hard-float": [
      "4148000000616561626900013e00000043322e30390005636f727465782d6d3400060d074d080009020a060e0011011204140115001703180119011a021b011c011e01220124012601",
      { cpuArch: 13, cpuArchProfile: 0x4d, vfpArgs: 1 },
    ],
    "armv7a hard-float": [
      "414c000000616561626900014200000043322e30390005636f727465782d613900060a0741080109020a030c010e0011011204140115001703180119011a021c011e012201240126012a014401",
      { cpuArch: 10, cpuArchProfile: 0x41, vfpArgs: 1 },
    ],
  } as const;

  it.each(Object.entries(CLANG))("reads %s", (_name, [hex, expected]) => {
    expect(parseArmBuildAttributes(Buffer.from(hex, "hex"), true)).toEqual(
      ok(expected),
    );
  });
});

describe("synthetic ARM build attribute sections", () => {
  it("skips tags it does not read by their parameter types", () => {
    expect(
      parse(
        file([
          67,
          ...text("2.09"),
          5,
          ...text("cortex-m7"),
          32,
          1,
          ...text("vendor"),
          64,
          0,
          65,
          ...text("\u0006\u000d"),
          0x44,
          ...uleb(300),
          6,
          13,
          7,
          0x4d,
          28,
          0,
        ]),
      ),
    ).toEqual(ok({ cpuArch: 13, cpuArchProfile: 0x4d, vfpArgs: 0 }));
  });

  it("skips other vendors and reads big-endian lengths", () => {
    expect(
      parse(
        section(
          subsection("ARM", [1, 2, 3], false),
          subsection("aeabi", scope(1, [6, 17], false), false),
        ),
        false,
      ),
    ).toEqual(ok({ cpuArch: 17, cpuArchProfile: null, vfpArgs: null }));
  });

  it("reads an aeabi subsection without declarations as undeclared", () => {
    expect(parse(file([]))).toEqual(
      ok({ cpuArch: null, cpuArchProfile: null, vfpArgs: null }),
    );
  });

  it.each([
    ["format version", Buffer.from([0x42]), "not A"],
    ["truncated length", Buffer.from([0x41, 5, 0]), "length is truncated"],
    [
      "oversized length",
      Buffer.from([0x41, ...u32(64, true), ...text("aeabi")]),
      "does not fit the section",
    ],
    [
      "unterminated vendor",
      Buffer.from([0x41, ...u32(9, true), ...Buffer.from("aeabi")]),
      "not terminated",
    ],
    [
      "two aeabi subsections",
      section(
        subsection("aeabi", scope(1, [6, 13])),
        subsection("aeabi", scope(1, [6, 13])),
      ),
      "more than one aeabi subsection",
    ],
    [
      "a section scope",
      section(subsection("aeabi", scope(2, [1, 0, 6, 13]))),
      "section- and symbol-scoped",
    ],
    [
      "a symbol scope",
      section(subsection("aeabi", scope(3, [1, 0, 6, 13]))),
      "section- and symbol-scoped",
    ],
    [
      "an undefined scope",
      section(subsection("aeabi", scope(4, []))),
      "scope tag 4 is not defined",
    ],
    [
      "a scope inside a scope",
      file([1, 6, 13]),
      "attribute tag 1 is not valid",
    ],
    ["a repeated tag", file([6, 13, 6, 13]), "declared more than once"],
    ["an unterminated string", file([5, 0x61]), "no terminated string"],
    ["a truncated value", file([6]), "malformed value"],
    [
      "an oversized value",
      file([6, 0xff, 0xff, 0xff, 0xff, 0x7f]),
      "malformed value",
    ],
    [
      "a scope past its subsection",
      section(subsection("aeabi", [1, ...u32(64, true)])),
      "does not fit its subsection",
    ],
  ] as const)("refuses %s", (_name, bytes, reason) => {
    const result = parse(bytes);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain(reason);
  });
});
