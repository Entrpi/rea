import { describe, expect, it } from "vitest";

import {
  ARM_BUILD_ATTRIBUTE_TAGS,
  ARM_CPU_ARCH_PROFILE_M,
  ARM_ELF_FLOAT_ABIS,
  ARM_ELF_M_PROFILE_ARCHITECTURES,
  armElfFloatAbi,
  armElfMProfile,
  type ArmBuildAttributes,
} from "./armBuildAttributes.js";
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
