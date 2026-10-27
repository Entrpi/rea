import { describe, expect, it } from "vitest";

import { ARM_ELF_FLOAT_ABIS } from "../domain/armBuildAttributes.js";
import { ARCHITECTURE_VARIANT_NAMES } from "../domain/architectureVariant.js";
import {
  GHIDRA_ARM_ELF_LANES,
  GHIDRA_ARM_ELF_VERIFIED_FLOAT_ABIS,
} from "./GhidraArmProfile.js";
import {
  GHIDRA_VARIANT_LANGUAGES,
  ghidraVariantProcessorLabels,
} from "./GhidraRawBinaryLanguage.js";

describe("M-profile ARM ELF lanes", () => {
  it("names one versioned lane per variant", () => {
    // Lane ids are persisted in analysis profiles; renaming one is a new lane.
    expect(GHIDRA_ARM_ELF_LANES).toEqual({
      "armv6-m": "elf32-exec-le-eabi5-armv6-m-pinned-v1",
      "armv7-m": "elf32-exec-le-eabi5-armv7-m-pinned-v1",
      "armv7e-m": "elf32-exec-le-eabi5-armv7e-m-pinned-v1",
      "armv8-m.base": "elf32-exec-le-eabi5-armv8-m.base-pinned-v1",
      "armv8-m.main": "elf32-exec-le-eabi5-armv8-m.main-pinned-v1",
      "armv8.1-m.main": "elf32-exec-le-eabi5-armv8.1-m.main-pinned-v1",
    });
    expect(Object.keys(GHIDRA_ARM_ELF_LANES)).toEqual(
      ARCHITECTURE_VARIANT_NAMES,
    );
  });

  it.each(ARCHITECTURE_VARIANT_NAMES)(
    "decodes %s with the raw-image decoder and label policy",
    (variant) => {
      expect(GHIDRA_VARIANT_LANGUAGES[variant]).toMatch(
        /^ARM:LE:32:(?:Cortex|v8-m)$/u,
      );
      expect(ghidraVariantProcessorLabels(variant)).toBe("not-applied-v1");
    },
  );

  it("verifies only VFP float passing", () => {
    expect(GHIDRA_ARM_ELF_VERIFIED_FLOAT_ABIS).toEqual(["vfp"]);
    for (const abi of GHIDRA_ARM_ELF_VERIFIED_FLOAT_ABIS)
      expect(ARM_ELF_FLOAT_ABIS).toContain(abi);
  });
});
