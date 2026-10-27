import type {
  RawArchitectureVariant,
  RawEntryIsaMode,
} from "../domain/rawArchitectureVariant.js";
import type { RawBinaryAdmission } from "../domain/rawBinary.js";

/** Bound Ghidra language for a caller-supplied raw-binary architecture. */
export interface GhidraRawBinaryLanguage {
  readonly languageId: string;
  readonly compilerSpecId: "default" | "gcc";
  readonly defaultAddressSpace: "ram" | "RAM";
}

/**
 * Ghidra decoder for each caller-named variant. `ARM:LE:32:Cortex` (the ARMv7
 * decoder with Thumb as the default state) has no ARMv8-M encodings such as
 * the MSPLIM and PSPLIM system registers, so v8-M variants use
 * `ARM:LE:32:v8-m`. Both languages share `ARMCortex.pspec`.
 */
export const GHIDRA_RAW_VARIANT_LANGUAGES = {
  "armv6-m": "ARM:LE:32:Cortex",
  "armv7-m": "ARM:LE:32:Cortex",
  "armv7e-m": "ARM:LE:32:Cortex",
  "armv8-m.base": "ARM:LE:32:v8-m",
  "armv8-m.main": "ARM:LE:32:v8-m",
} as const satisfies Record<RawArchitectureVariant, string>;

/** Ghidra context register and value that select each entry instruction set. */
export const GHIDRA_RAW_ENTRY_CONTEXT = {
  thumb: { register: "TMode", value: "0x1" },
} as const satisfies Record<
  RawEntryIsaMode,
  { readonly register: string; readonly value: string }
>;

/**
 * Map caller-visible CPU families to generic Ghidra languages with a
 * supported generic compiler specification. These are analysis conventions,
 * not evidence of the target's original compiler. Each family has one fixed
 * byte order: m68k is big-endian and the others are little-endian. A
 * caller-named variant selects its own decoder instead of the generic one;
 * big-endian ARM and unnamed processor variants are out of scope.
 */
export const ghidraRawBinaryLanguage = (
  architecture: RawBinaryAdmission["architecture"],
  variant?: RawArchitectureVariant,
): GhidraRawBinaryLanguage => {
  if (variant !== undefined)
    return {
      languageId: GHIDRA_RAW_VARIANT_LANGUAGES[variant],
      compilerSpecId: "default",
      defaultAddressSpace: "ram",
    };
  switch (architecture) {
    case "6502":
      return {
        languageId: "6502:LE:16:default",
        compilerSpecId: "default",
        defaultAddressSpace: "RAM",
      };
    case "m68k":
      // Ghidra's default 68000 language decodes the 68040 superset; no
      // MC68000-only variant is declared in the 68000 processor module.
      return {
        languageId: "68000:BE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "x86":
      return {
        languageId: "x86:LE:32:default",
        compilerSpecId: "gcc",
        defaultAddressSpace: "ram",
      };
    case "x86_64":
      return {
        languageId: "x86:LE:64:default",
        compilerSpecId: "gcc",
        defaultAddressSpace: "ram",
      };
    case "arm":
      return {
        languageId: "ARM:LE:32:v7",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "arm64":
      return {
        languageId: "AARCH64:LE:64:v8A",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
  }
};
