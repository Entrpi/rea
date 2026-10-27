import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { RiscvFloatAbi } from "../domain/riscvIsaDeclaration.js";
import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";

/** Calling-convention policy ids an analysis profile can commit. */
export const GHIDRA_RISCV_CALLING_CONVENTION_IDS = [
  "ilp32-prototype-v1",
] as const;
export type GhidraRiscvCallingConvention =
  (typeof GHIDRA_RISCV_CALLING_CONVENTION_IDS)[number];

/**
 * The ABI and prototype of each policy REA applies after analysis.
 * `ReaGhidraRiscvCallingConvention.java` derives each prototype from the
 * pinned language's default `riscv32-fp.cspec` model, which is ilp32d;
 * docs/ghidra-riscv.md states the rules of each ABI.
 */
export const GHIDRA_RISCV_CALLING_CONVENTIONS: Readonly<
  Record<
    GhidraRiscvCallingConvention,
    { readonly abi: string; readonly prototype: string }
  >
> = {
  "ilp32-prototype-v1": { abi: "ilp32", prototype: "__rea_ilp32" },
};

/** One admitted ELF class and declared float ABI. */
export interface GhidraRiscvLane {
  readonly elfClass: 32 | 64;
  readonly floatAbi: RiscvFloatAbi;
  /** Absent: Ghidra's stock double-float model applies unchanged. */
  readonly callingConvention?: GhidraRiscvCallingConvention;
}

/** Every class and float ABI pair the Ghidra lane admits; others are refused. */
export const GHIDRA_RISCV_LANES: readonly GhidraRiscvLane[] = [
  { elfClass: 64, floatAbi: "double" },
  { elfClass: 32, floatAbi: "double" },
  { elfClass: 32, floatAbi: "soft", callingConvention: "ilp32-prototype-v1" },
];

/** Lane ids are built from their fields, so a new ABI or load model adds a value. */
export const ghidraRiscvSupportLane = (lane: GhidraRiscvLane): string =>
  `elf${lane.elfClass}-exec-le-${lane.floatAbi}-float-generic-v1`;

/**
 * Extensions Ghidra 12.1.4's generic RV32 language implements with p-code, by
 * the names `Tag_RISCV_arch` records. Lanes with a calling-convention policy
 * admit an image only when it declares an RV32I base and only these.
 */
export const GHIDRA_RISCV32_DECODED_EXTENSIONS: ReadonlySet<string> = new Set([
  "m",
  "a",
  "f",
  "d",
  "c",
  "zicsr",
  "zifencei",
  "zmmul",
  "zaamo",
  "zalrsc",
  "zca",
  "zcf",
  "zcd",
]);

/** Outcome the post-analysis script records for the bridge handshake. */
export interface GhidraRiscvCallingConventionReport {
  readonly policy: GhidraRiscvCallingConvention;
  readonly functions: number;
  readonly definitions: number;
}

/**
 * Ghidra's generic RISC-V languages model the double-float ABI: the shipped
 * `riscv.ldefs` maps `RISCV:LE:{32,64}:default` to the `riscv{32,64}-fp.cspec`
 * compiler specification. Soft, single and quad ABI declarations therefore need
 * their own verification rather than inheriting this lane.
 */
const EF_RISCV_RVC = 0x0001;
const EF_RISCV_FLOAT_ABI = 0x0006;
const EF_RISCV_FLOAT_ABI_DOUBLE = 0x0004;
const EF_RISCV_RVE = 0x0008;
const EF_RISCV_TSO = 0x0010;

const ET_REL = 1;
const ET_EXEC = 2;
const ET_DYN = 3;

/**
 * Bits this lane reads. Anything else in `e_flags` — reserved today or defined by
 * a newer psABI — is refused rather than assumed compatible.
 */
const EF_RISCV_DECLARED_BITS = EF_RISCV_RVC | EF_RISCV_FLOAT_ABI;

/** Header declarations outside the verified generic-language lane. */
const riscvUnsupportedFloatAbi = (abi: number): string =>
  abi === 0
    ? "unspecified (soft-float convention)"
    : abi === 0x0002
      ? "single-float"
      : "quad-float";

/**
 * Keep family recognition separate from the deliberately bounded Ghidra lane.
 *
 * Ghidra 12.1.4 selects `RISCV:LE:32:AndeStar_v5` for an ordinary RV32 ELF: its
 * `riscv.opinion` pins `variant="default"` for the 64-bit constraint and leaves
 * the 32-bit one with the comment that the loader "must choose between 'default'
 * and 'AndeStar' variants". The lane therefore pins the language instead of
 * accepting the header-based guess.
 */
export const ghidraRiscvUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (target.kind !== "executable" || target.architecture !== "riscv")
    return null;
  const metadata = target.riscv;
  if (target.format !== "elf")
    return "RISC-V analysis requires ELF header metadata; a family name alone does not select an ISA or ABI.";
  if (metadata.byteOrder !== "little")
    return "This Ghidra RISC-V lane supports little-endian images only; Ghidra 12.1.4 ships no big-endian RISC-V language.";
  if (metadata.elfClass !== 32 && metadata.elfClass !== 64)
    return "This Ghidra RISC-V lane requires ELF32 or ELF64; the class decides which generic language is pinned.";
  if ((metadata.flags & EF_RISCV_RVE) !== 0)
    return "EF_RISCV_RVE declares the embedded 15-register ABI, which needs its own processor specification and compiler verification.";
  if ((metadata.flags & EF_RISCV_TSO) !== 0)
    return "EF_RISCV_TSO declares the total-store-order memory model; this lane verifies the baseline model only.";
  if (metadata.type !== ET_EXEC)
    return `This Ghidra RISC-V lane supports fixed-address ET_EXEC only; ${
      metadata.type === ET_REL
        ? "relocatable"
        : metadata.type === ET_DYN
          ? "shared and position-independent"
          : `e_type ${metadata.type}`
    } images need separate load verification. ET_EXEC alone does not establish static linkage, which this lane does not inspect.`;
  const abi = metadata.flags & EF_RISCV_FLOAT_ABI;
  if (abi !== EF_RISCV_FLOAT_ABI_DOUBLE)
    return `This Ghidra RISC-V lane requires the EF_RISCV_FLOAT_ABI_DOUBLE declaration (${riscvUnsupportedFloatAbi(
      abi,
    )} observed); the pinned generic language uses the double-float compiler specification.`;
  const unsupportedFlags = (metadata.flags & ~EF_RISCV_DECLARED_BITS) >>> 0;
  if (unsupportedFlags !== 0)
    return `RISC-V e_flags declares bits outside the verified lane (0x${unsupportedFlags.toString(16)}); reserved or newer declarations are not treated as compatible with this profile.`;
  return null;
};

/** Pin a language only for declarations admitted by the same lane boundary. */
export const ghidraRiscvLanguageOverride = (
  target: BinaryTarget,
): GhidraLanguageOverride | undefined =>
  target.kind === "executable" &&
  target.architecture === "riscv" &&
  ghidraRiscvUnsupportedReason(target) === null
    ? {
        languageId: `RISCV:LE:${target.riscv.elfClass}:default`,
        compilerSpecId: "gcc",
      }
    : undefined;

/** Commit source ELF interpretation without confusing target ISA with host CPU. */
export const ghidraRiscvProfileParameters = (
  target: BinaryTarget,
): Readonly<Record<string, JsonValue>> =>
  target.kind === "executable" &&
  target.architecture === "riscv" &&
  target.riscv !== undefined
    ? {
        riscv_elf: {
          elf_class: target.riscv.elfClass,
          byte_order: target.riscv.byteOrder,
          type: target.riscv.type,
          flags: target.riscv.flags,
          float_abi_double:
            (target.riscv.flags & EF_RISCV_FLOAT_ABI) ===
            EF_RISCV_FLOAT_ABI_DOUBLE,
          rvc_declared: (target.riscv.flags & EF_RISCV_RVC) !== 0,
          rve_declared: (target.riscv.flags & EF_RISCV_RVE) !== 0,
          tso_declared: (target.riscv.flags & EF_RISCV_TSO) !== 0,
        },
        riscv_support_lane: ghidraRiscvSupportLane({
          elfClass: target.riscv.elfClass,
          floatAbi: "double",
        }),
      }
    : {};

/** The pinned language is an analysis convention, not proof of the producer. */
export const ghidraRiscvLimitations = (
  target: BinaryTarget,
): readonly string[] =>
  target.kind === "executable" && target.architecture === "riscv"
    ? [
        `RISC-V ELF: REA pins Ghidra's generic \`RISCV:LE:${target.riscv.elfClass}:default\` language with the \`gcc\` compiler specification instead of accepting the loader's header-based choice, which selects \`RISCV:LE:32:AndeStar_v5\` for ordinary RV32 images on Ghidra 12.1.4.`,
        "The pinned generic language models the double-float ABI declared by `e_flags`; the declaration is recorded as an ELF fact and is not evidence of the original compiler or of verified instruction semantics.",
        "Admission reads `e_type` only: a fixed-address ET_EXEC declaration does not establish static linkage, and program headers (`PT_INTERP`, dynamic dependencies) are not inspected by this lane.",
      ]
    : [];
