import type {
  RawArchitectureVariant,
  RawEntryIsaMode,
} from "../domain/rawArchitectureVariant.js";
import type { RawBinaryLoad } from "../domain/binaryTargetTypes.js";
import {
  isLegacyRawLoad,
  type RawBinaryAdmission,
} from "../domain/rawBinary.js";

/** Bound Ghidra language for a caller-supplied raw-binary architecture. */
export interface GhidraRawBinaryLanguage {
  readonly languageId: string;
  readonly compilerSpecId: "default" | "gcc";
  readonly defaultAddressSpace: "ram" | "RAM";
}

/**
 * Ghidra decoder for each caller-named variant. `ARM:LE:32:Cortex` (the ARMv7
 * decoder with Thumb as the default state) has no ARMv8-M encodings such as
 * the MSPLIM and PSPLIM system registers, so v8-M and v8.1-M variants use
 * `ARM:LE:32:v8-m`, which Ghidra 12.1.4's `ARM.ldefs` also lists for
 * `armv8.1-m.main`. Both languages share `ARMCortex.pspec`.
 */
export const GHIDRA_RAW_VARIANT_LANGUAGES = {
  "armv6-m": "ARM:LE:32:Cortex",
  "armv7-m": "ARM:LE:32:Cortex",
  "armv7e-m": "ARM:LE:32:Cortex",
  "armv8-m.base": "ARM:LE:32:v8-m",
  "armv8-m.main": "ARM:LE:32:v8-m",
  "armv8.1-m.main": "ARM:LE:32:v8-m",
} as const satisfies Record<RawArchitectureVariant, string>;

/**
 * Ghidra context register and value that select each entry instruction set,
 * and the versioned profile commitment that the entry is seeded with them.
 */
export const GHIDRA_RAW_ENTRY_CONTEXT = {
  thumb: {
    register: "TMode",
    value: "0x1",
    commitment: "thumb-tmode-1-before-analysis-v1",
  },
} as const satisfies Record<
  RawEntryIsaMode,
  {
    readonly register: string;
    readonly value: string;
    readonly commitment: string;
  }
>;

/**
 * Profile commitment that a variant load is imported without the language's
 * default labels. `ARMCortex.pspec` names the vector table at `ram:0x0`-`0x40`
 * and marks every handler slot an entry, reserved slots included; at a base of
 * 0 those labels would fall inside the image and over the code after the table.
 * Admission reads the vector table itself. Undefined keeps the language default.
 */
export const ghidraRawProcessorLabels = (
  variant: RawArchitectureVariant | undefined,
): "not-applied-v1" | undefined =>
  variant === undefined ? undefined : "not-applied-v1";

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

const GENERIC_RAW_LANGUAGES =
  "Little-endian generic Ghidra languages are used for x86, x86_64, arm, arm64, and NMOS 6502; m68k uses the big-endian 68000 default language, which decodes the 68040 superset. Big-endian ARM, 65C02, 65816, separate 68020/68030/CPU32/ColdFire variants, and other processor variants are unsupported; ARM M-profile code needs architecture_variant.";

/**
 * Observed with Ghidra 12.1.4 on the verifier's Cortex-M55 image: WLS and LE
 * decode with LLVM's mnemonics, but WLS branched 2 bytes short, LE branched 4
 * bytes past the loop start, and LE had no fall-through, so the code after the
 * loop was not disassembled.
 */
const GHIDRA_LOW_OVERHEAD_LOOPS =
  "Ghidra 12.1.4 decodes the ARMv8.1-M low-overhead-loop branches WLS and LE, but their targets can be wrong and LE has no fall-through, so code after such a loop may be left undisassembled.";

/** Limitations that every result from a raw-binary session carries. */
export const ghidraRawBinaryLimitations = (
  load: RawBinaryLoad,
  language: GhidraRawBinaryLanguage,
): string[] =>
  isLegacyRawLoad(load)
    ? [
        "Headerless raw-binary analysis uses the caller-supplied architecture and entry address; file offset 0 is mapped at that address. Headers are not discovered from file bytes.",
        GENERIC_RAW_LANGUAGES,
        "Static analysis does not emulate reset vectors, memory-mapped I/O, or firmware boot sequences.",
      ]
    : [
        `Headerless raw-binary analysis maps file offset 0 at ${load.baseAddress} and seeds the entry ${load.entryPoint}. Headers are not discovered from file bytes.`,
        load.architectureVariant === undefined
          ? GENERIC_RAW_LANGUAGES
          : `The caller-named ${load.architectureVariant} variant is decoded with ${language.languageId} in Thumb state. The decoder does not refuse instructions that this profile lacks, and floating-point and TrustZone state are not modeled.`,
        ...(load.architectureVariant === "armv8.1-m.main"
          ? [GHIDRA_LOW_OVERHEAD_LOOPS]
          : []),
        ...(load.entrySource.kind === "vector-table"
          ? [
              `The entry is the Reset vector ${load.entrySource.resetVector} read from the vector table at ${load.entrySource.address}, with bit 0 cleared. The initial stack pointer ${load.entrySource.initialStackPointer} is recorded and not validated.`,
            ]
          : []),
        "Only the file is mapped. SRAM, peripheral and system blocks are not created; Ghidra's processor-defined vector labels are not applied, so vectors other than Reset are neither labels nor entries; and reset, memory-mapped I/O, and boot sequences are not emulated.",
      ];
