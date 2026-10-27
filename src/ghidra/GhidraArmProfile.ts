import type { ArmElfFloatAbi } from "../domain/armBuildAttributes.js";
import type { ArchitectureVariant } from "../domain/architectureVariant.js";

/**
 * One versioned lane per M profile for little-endian EABI5 ARM ELF
 * executables. The decoder of each lane is its variant's in
 * `GHIDRA_VARIANT_LANGUAGES`, with the limitations in
 * `GHIDRA_VARIANT_LIMITATIONS`, and its label policy is
 * `ghidraVariantProcessorLabels`; this table only names the lanes.
 */
export const GHIDRA_ARM_ELF_LANES = {
  "armv6-m": "elf32-exec-le-eabi5-armv6-m-pinned-v1",
  "armv7-m": "elf32-exec-le-eabi5-armv7-m-pinned-v1",
  "armv7e-m": "elf32-exec-le-eabi5-armv7e-m-pinned-v1",
  "armv8-m.base": "elf32-exec-le-eabi5-armv8-m.base-pinned-v1",
  "armv8-m.main": "elf32-exec-le-eabi5-armv8-m.main-pinned-v1",
  "armv8.1-m.main": "elf32-exec-le-eabi5-armv8.1-m.main-pinned-v1",
} as const satisfies Record<ArchitectureVariant, string>;

/**
 * Prototypes of Ghidra's ARM compiler specification that the DWARF analyzer
 * gives the signatures it imports, by float ABI; the analyzer's default stays
 * for any other. `ARM.cspec` defines `__stdcall_softfp` for `-mfloat-abi=soft`
 * and `softfp`: floating-point arguments and results pass in core registers,
 * as the base standard declares.
 */
export const GHIDRA_ARM_ELF_DWARF_PROTOTYPES = {
  base: {
    callingConvention: "__stdcall_softfp",
    commitment: "dwarf-default-stdcall-softfp-v1",
  },
} as const satisfies Partial<
  Record<
    ArmElfFloatAbi,
    { readonly callingConvention: string; readonly commitment: string }
  >
>;

/**
 * Float ABIs whose argument and result passing the real lane checks against
 * the default prototype of Ghidra's ARM compiler specification, which passes
 * floating-point values in VFP registers. Every other declaration stays
 * admitted under its lane with a limitation that names it, and says when its
 * DWARF signatures use another prototype.
 */
export const GHIDRA_ARM_ELF_VERIFIED_FLOAT_ABIS = [
  "vfp",
] as const satisfies readonly ArmElfFloatAbi[];
