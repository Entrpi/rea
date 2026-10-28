import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import {
  EF_ARM_BE8,
  EF_ARM_EABI_MASK,
  EF_ARM_EABI_VER5,
  armElfFloatAbi,
  armElfMProfile,
  type ArmElfFloatAbi,
  type ArmElfMProfile,
} from "../domain/armBuildAttributes.js";
import type {
  ArmElfMetadata,
  BinaryTarget,
} from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { ArchitectureVariant } from "../domain/architectureVariant.js";
import {
  GHIDRA_VARIANT_LANGUAGES,
  ghidraVariantDecoderLimitations,
  ghidraVariantProcessorLabels,
} from "./GhidraRawBinaryLanguage.js";

/**
 * One versioned lane per M profile for little-endian EABI5 ARM ELF
 * executables. The decoder of each lane is its variant's in
 * `GHIDRA_VARIANT_LANGUAGES`, and its label policy is
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

const ET_EXEC = 2;

/** The lane an ARM ELF target selects, or why Ghidra's header selection stays. */
export type GhidraArmElfLane =
  | {
      readonly kind: "pinned";
      readonly profile: Extract<ArmElfMProfile, { kind: "m-profile" }>;
      readonly language: GhidraLanguageOverride & {
        readonly compilerSpecId: "default";
      };
      readonly lane: (typeof GHIDRA_ARM_ELF_LANES)[ArchitectureVariant];
    }
  /** `reason` is present only when an M profile is declared or unknown. */
  | { readonly kind: "header-selected"; readonly reason?: string };

const loadShapeIssue = (arm: ArmElfMetadata): string | undefined =>
  arm.elfClass !== 32 || arm.byteOrder !== "little"
    ? "the lane covers little-endian ELF32 images only"
    : arm.type !== ET_EXEC
      ? `the lane covers ET_EXEC images only, and e_type is ${arm.type}`
      : (arm.flags & EF_ARM_EABI_MASK) >>> 0 !== EF_ARM_EABI_VER5
        ? "the lane covers EABI version 5 images only"
        : (arm.flags & EF_ARM_BE8) !== 0
          ? "the lane does not cover EF_ARM_BE8 images"
          : undefined;

const declaredProfile = (arm: ArmElfMetadata): ArmElfMProfile => {
  const { attributes } = arm;
  if (attributes === undefined)
    return { kind: "unknown", reason: "REA did not read .ARM.attributes" };
  switch (attributes.status) {
    case "absent":
      return {
        kind: "unknown",
        reason: "the image has no .ARM.attributes section",
      };
    case "unavailable":
      return {
        kind: "unknown",
        reason: `REA could not read .ARM.attributes: ${attributes.reason}`,
      };
    case "declared":
      return armElfMProfile(attributes.declarations);
  }
};

/** Select the lane from the target's facts; the one owner of that choice. */
export const ghidraArmElfLane = (
  target: BinaryTarget,
): GhidraArmElfLane | undefined => {
  if (
    target.kind !== "executable" ||
    target.format !== "elf" ||
    target.architecture !== "arm"
  )
    return undefined;
  const profile = declaredProfile(target.arm);
  const shape = loadShapeIssue(target.arm);
  if (profile.kind === "other-profile") return { kind: "header-selected" };
  if (profile.kind === "unknown")
    return shape === undefined
      ? { kind: "header-selected", reason: profile.reason }
      : { kind: "header-selected" };
  if (shape !== undefined)
    return {
      kind: "header-selected",
      reason: `.ARM.attributes declares ${profile.architecture.label} (${profile.variant}), but ${shape}`,
    };
  return {
    kind: "pinned",
    profile,
    language: {
      languageId: GHIDRA_VARIANT_LANGUAGES[profile.variant],
      compilerSpecId: "default",
    },
    lane: GHIDRA_ARM_ELF_LANES[profile.variant],
  };
};

/** The import language this target's lane pins, if any. */
export const ghidraArmLanguageOverride = (
  target: BinaryTarget,
): GhidraLanguageOverride | undefined => {
  const lane = ghidraArmElfLane(target);
  return lane?.kind === "pinned" ? lane.language : undefined;
};

const floatAbi = (arm: ArmElfMetadata): ArmElfFloatAbi =>
  armElfFloatAbi(
    arm.flags,
    arm.attributes?.status === "declared"
      ? arm.attributes.declarations.vfpArgs
      : null,
  );

const DWARF_PROTOTYPES: Partial<
  Record<
    ArmElfFloatAbi,
    { readonly callingConvention: string; readonly commitment: string }
  >
> = GHIDRA_ARM_ELF_DWARF_PROTOTYPES;

/** The prototype DWARF signatures use for this image's float ABI, if not the default. */
const dwarfPrototype = (arm: ArmElfMetadata) => DWARF_PROTOTYPES[floatAbi(arm)];

/**
 * Commit the lane and the ELF facts that selected it. A caller-selected
 * language wins over the pin, and the profile then stays the one that
 * the override produced before this lane existed.
 */
export const ghidraArmProfileParameters = (
  target: BinaryTarget,
  languageOverride?: GhidraLanguageOverride,
): Readonly<Record<string, JsonValue>> => {
  const lane = ghidraArmElfLane(target);
  if (
    lane?.kind !== "pinned" ||
    languageOverride !== undefined ||
    target.kind !== "executable" ||
    target.format !== "elf" ||
    target.architecture !== "arm"
  )
    return {};
  const { arm } = target;
  const labels = ghidraVariantProcessorLabels(lane.profile.variant);
  const prototype = dwarfPrototype(arm);
  return {
    arm_elf: {
      elf_class: arm.elfClass,
      byte_order: arm.byteOrder,
      type: arm.type,
      flags: arm.flags,
      cpu_arch: lane.profile.architecture.cpuArch,
      cpu_arch_profile:
        arm.attributes?.status === "declared"
          ? arm.attributes.declarations.cpuArchProfile
          : null,
    },
    arm_support_lane: lane.lane,
    ...(labels === undefined ? {} : { processor_labels: labels }),
    ...(prototype === undefined
      ? {}
      : { arm_float_prototype: prototype.commitment }),
  };
};

/**
 * Whether a committed profile carries the lane, label policy and DWARF
 * prototype that this target selects.
 */
export const ghidraArmProfileMismatchReason = (
  target: BinaryTarget,
  parameters: Readonly<Record<string, unknown>>,
): string | null => {
  const lane = ghidraArmElfLane(target);
  if (
    lane === undefined ||
    target.kind !== "executable" ||
    target.format !== "elf" ||
    target.architecture !== "arm"
  )
    return null;
  const pinned =
    lane.kind === "pinned" &&
    parameters.language_selection === "provider-pinned-v1"
      ? lane
      : undefined;
  return parameters.arm_support_lane === pinned?.lane &&
    parameters.processor_labels ===
      (pinned === undefined
        ? undefined
        : ghidraVariantProcessorLabels(pinned.profile.variant)) &&
    parameters.arm_float_prototype ===
      (pinned === undefined
        ? undefined
        : dwarfPrototype(target.arm)?.commitment)
    ? null
    : "Resolve the M-profile ARM ELF lane for this target into a fresh analysis profile before opening the session.";
};

/** The prototype a committed profile gives DWARF signatures, for the launcher. */
export const ghidraArmDwarfCallingConvention = (
  parameters: Readonly<Record<string, unknown>>,
): string | undefined =>
  Object.values(GHIDRA_ARM_ELF_DWARF_PROTOTYPES).find(
    ({ commitment }) => commitment === parameters.arm_float_prototype,
  )?.callingConvention;

/** What ReaGhidraDwarfCallingConvention.java reports during the handshake. */
export interface GhidraDwarfCallingConventionReport {
  readonly calling_convention: string;
  readonly status: "applied" | "not_applicable";
}

/** Fail closed unless the session applied exactly the committed prototype. */
export const ghidraArmDwarfCallingConventionFailure = (
  expected: string | undefined,
  report: GhidraDwarfCallingConventionReport | undefined,
): string | undefined =>
  expected === report?.calling_convention
    ? undefined
    : expected === undefined
      ? "The Ghidra session reported a DWARF calling convention that the profile did not commit."
      : `The Ghidra session did not report the committed DWARF calling convention ${expected}.`;

/** The outcome the session states once the handshake reports it. */
export const ghidraArmDwarfCallingConventionLimitations = (
  report: GhidraDwarfCallingConventionReport | undefined,
): readonly string[] =>
  report?.status === "not_applicable"
    ? [
        `The image carries no DWARF, so no signature uses ${report.calling_convention}; Ghidra infers parameters from the registers the code uses.`,
      ]
    : [];

const UNVERIFIED =
  "REA has not verified it against Ghidra's default ARM prototype, which passes floating-point arguments and results in VFP registers.";

/** What the session states about a float ABI that the lane has not verified with the default prototype. */
const FLOAT_ABI_LIMITATIONS: Readonly<Record<ArmElfFloatAbi, string>> = {
  vfp: `The image declares the VFP procedure-call standard (hard-float). ${UNVERIFIED}`,
  base: `The image declares the base procedure-call standard (soft-float or softfp): floating-point arguments and results pass in r0-r3. REA sets the DWARF analyzer's default calling convention to Ghidra's ${GHIDRA_ARM_ELF_DWARF_PROTOTYPES.base.callingConvention}, so the signatures it imports keep their float and double types in core registers. A float prototype from any other source keeps Ghidra's default ARM prototype, which passes floating-point values in VFP registers.`,
  compatible: `The image declares that no floating-point value crosses a non-variadic interface (Tag_ABI_VFP_args 3). ${UNVERIFIED}`,
  toolchain: `The image declares a toolchain-specific floating-point convention (Tag_ABI_VFP_args 2). ${UNVERIFIED}`,
  unresolved: `The image declares floating-point conventions that disagree, or a reserved Tag_ABI_VFP_args value. ${UNVERIFIED}`,
  undeclared: `The image declares no floating-point calling convention in its header or attributes. ${UNVERIFIED}`,
};

const floatAbiLimitation = (arm: ArmElfMetadata): readonly string[] => {
  const abi = floatAbi(arm);
  return (GHIDRA_ARM_ELF_VERIFIED_FLOAT_ABIS as readonly string[]).includes(abi)
    ? []
    : [FLOAT_ABI_LIMITATIONS[abi]];
};

/** What the session must state about the lane, given the committed profile. */
export const ghidraArmLimitations = (
  target: BinaryTarget,
  parameters: Readonly<Record<string, unknown>>,
): readonly string[] => {
  const lane = ghidraArmElfLane(target);
  if (
    lane === undefined ||
    target.kind !== "executable" ||
    target.format !== "elf" ||
    target.architecture !== "arm"
  )
    return [];
  const configured = parameters.language_selection === "configured-v1";
  if (lane.kind === "header-selected")
    return lane.reason === undefined || configured
      ? []
      : [
          `ARM ELF: REA did not select an M-profile decoder because ${lane.reason}. Ghidra selects the language from the ELF header; its default instruction state is ARM, so code that no entry or symbol marks as Thumb decodes in ARM state.`,
        ];
  const { architecture, variant } = lane.profile;
  if (configured)
    return [
      `ARM ELF: the configured language ${String(parameters.language_id)} replaces ${lane.language.languageId}, which REA pins for the ${variant} profile that .ARM.attributes declares.`,
    ];
  return [
    `ARM ELF: .ARM.attributes declares ${architecture.label} (Tag_CPU_arch ${architecture.cpuArch}), so REA pins ${lane.language.languageId} for the ${variant} profile instead of Ghidra's header-based selection, whose default instruction state is ARM. The decoder does not refuse instructions that this profile lacks, and floating-point, TrustZone and memory-protection state are not modelled.`,
    ...ghidraVariantDecoderLimitations(variant),
    "Ghidra's processor-defined vector labels are not applied, so only the ELF's own symbols name vector-table slots and handlers. In a stripped image, a handler that only the vector table references can stay without a function; an analysis seed (REA_GHIDRA_SEED_FILE) can name it.",
    ...floatAbiLimitation(target.arm),
  ];
};
