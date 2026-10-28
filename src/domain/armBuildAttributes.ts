import type { ArchitectureVariant } from "./architectureVariant.js";
import { err, ok, type Result } from "./result.js";

/**
 * Public AEABI build-attribute tags that REA reads from the file scope of an
 * ARM ELF's `.ARM.attributes` section. Every other tag is skipped by its
 * declared parameter type and never interpreted.
 */
export const ARM_BUILD_ATTRIBUTE_TAGS = {
  cpuArch: 6,
  cpuArchProfile: 7,
  vfpArgs: 28,
} as const;

/** File-scope declarations of the tags REA reads; null when the file scope omits one. */
export interface ArmBuildAttributes {
  /** Tag_CPU_arch, the architecture version. */
  readonly cpuArch: number | null;
  /** Tag_CPU_arch_profile as its character code: 0x41 A, 0x52 R, 0x4d M, 0x53 S, or 0. */
  readonly cpuArchProfile: number | null;
  /** Tag_ABI_VFP_args, how floating-point arguments and results are passed. */
  readonly vfpArgs: number | null;
}

/** Bound the section read before its declared size can drive allocation. */
export const ARM_BUILD_ATTRIBUTES_MAX_BYTES = 0x10000;

const FORMAT_VERSION = 0x41;
const TAG_FILE = 1;
const TAG_SYMBOL = 3;
const TAG_CPU_RAW_NAME = 4;
const TAG_CPU_NAME = 5;
const TAG_COMPATIBILITY = 32;
const READ_TAGS: ReadonlyMap<number, keyof ArmBuildAttributes> = new Map(
  Object.entries(ARM_BUILD_ATTRIBUTE_TAGS).map(([field, tag]) => [
    tag,
    field as keyof ArmBuildAttributes,
  ]),
);

type Declarations = Record<keyof ArmBuildAttributes, number | null>;

/** Bounded readers over one attribute section, in the containing ELF's byte order. */
const attributeReader = (bytes: Buffer, littleEndian: boolean) => ({
  bytes,
  u32: (offset: number): number =>
    littleEndian ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset),
  uleb: (
    offset: number,
    end: number,
  ): { readonly value: number; readonly next: number } | undefined => {
    let value = 0;
    for (let index = 0; index < 5 && offset + index < end; index += 1) {
      const byte = bytes[offset + index]!;
      value += (byte & 0x7f) * 2 ** (7 * index);
      if ((byte & 0x80) === 0)
        return value <= 0xffffffff
          ? { value, next: offset + index + 1 }
          : undefined;
    }
    return undefined;
  },
  /** The offset after a NUL-terminated string that ends before `end`. */
  string: (offset: number, end: number): number | undefined => {
    const terminator = bytes.indexOf(0, offset);
    return terminator < 0 || terminator >= end ? undefined : terminator + 1;
  },
});
type AttributeReader = ReturnType<typeof attributeReader>;

/**
 * Read one attribute at `cursor`; returns the next offset or an error. The
 * parameter types follow the AEABI: Tag_CPU_raw_name and Tag_CPU_name are
 * strings, Tag_compatibility is a flag and a vendor name, other tags below 32
 * are ULEB128 values, and from 32 odd tags are strings and even tags values.
 */
const readAttribute = (
  reader: AttributeReader,
  cursor: number,
  end: number,
  declarations: Declarations,
): number | string => {
  const tag = reader.uleb(cursor, end);
  if (tag === undefined) return "an attribute tag is malformed";
  if (tag.value <= TAG_SYMBOL)
    return `attribute tag ${tag.value} is not valid in a scope`;
  if (
    tag.value === TAG_CPU_RAW_NAME ||
    tag.value === TAG_CPU_NAME ||
    (tag.value > TAG_COMPATIBILITY && tag.value % 2 === 1)
  )
    return (
      reader.string(tag.next, end) ??
      `attribute tag ${tag.value} has no terminated string`
    );
  const value = reader.uleb(tag.next, end);
  if (value === undefined)
    return `attribute tag ${tag.value} has a malformed value`;
  if (tag.value === TAG_COMPATIBILITY)
    return (
      reader.string(value.next, end) ??
      "Tag_compatibility has no terminated vendor name"
    );
  const field = READ_TAGS.get(tag.value);
  if (field === undefined) return value.next;
  if (declarations[field] !== null)
    return `attribute tag ${tag.value} is declared more than once`;
  declarations[field] = value.value;
  return value.next;
};

/** Read the scopes of the aeabi subsection; returns an error, or undefined. */
const readAeabiScopes = (
  reader: AttributeReader,
  start: number,
  end: number,
  declarations: Declarations,
): string | undefined => {
  let cursor = start;
  while (cursor < end) {
    const scopeStart = cursor;
    const scope = reader.uleb(cursor, end);
    if (scope === undefined || end - scope.next < 4)
      return "an attribute scope is truncated";
    if (scope.value !== TAG_FILE)
      return scope.value > TAG_FILE && scope.value <= TAG_SYMBOL
        ? "section- and symbol-scoped attributes are not read"
        : `attribute scope tag ${scope.value} is not defined`;
    const scopeEnd = scopeStart + reader.u32(scope.next);
    if (scopeEnd < scope.next + 4 || scopeEnd > end)
      return "an attribute scope length does not fit its subsection";
    cursor = scope.next + 4;
    while (cursor < scopeEnd) {
      const next = readAttribute(reader, cursor, scopeEnd, declarations);
      if (typeof next === "string") return next;
      cursor = next;
    }
  }
  return undefined;
};

/**
 * Read the public `aeabi` file-scope declarations of a `.ARM.attributes`
 * section. Other vendors' subsections are skipped, as the AEABI allows.
 * Section and symbol scopes, repeated declarations and malformed encodings
 * fail, so a declaration is never attributed to the whole file by guess.
 */
export const parseArmBuildAttributes = (
  bytes: Buffer,
  littleEndian: boolean,
): Result<ArmBuildAttributes, string> => {
  if (bytes.length === 0 || bytes[0] !== FORMAT_VERSION)
    return err("the attribute section format version is not A");
  const reader = attributeReader(bytes, littleEndian);
  const declarations: Declarations = {
    cpuArch: null,
    cpuArchProfile: null,
    vfpArgs: null,
  };
  let publicSeen = false;
  let position = 1;
  while (position < bytes.length) {
    if (bytes.length - position < 4)
      return err("an attribute subsection length is truncated");
    const length = reader.u32(position);
    if (length < 5 || length > bytes.length - position)
      return err("an attribute subsection length does not fit the section");
    const end = position + length;
    const vendorEnd = reader.string(position + 4, end);
    if (vendorEnd === undefined)
      return err("an attribute vendor name is not terminated");
    const vendor = bytes.toString("latin1", position + 4, vendorEnd - 1);
    position = end;
    if (vendor !== "aeabi") continue;
    if (publicSeen)
      return err("the section has more than one aeabi subsection");
    publicSeen = true;
    const failure = readAeabiScopes(reader, vendorEnd, end, declarations);
    if (failure !== undefined) return err(failure);
  }
  return ok(declarations);
};

/** Tag_CPU_arch_profile value of the microcontroller profile, the character M. */
export const ARM_CPU_ARCH_PROFILE_M = 0x4d;

/**
 * M-profile architectures that Tag_CPU_arch declares, each mapped to a variant
 * of the shared vocabulary (`architectureVariant.ts`), which owns the names.
 * ARMv7 spans the A, R and M profiles, so it maps only with
 * Tag_CPU_arch_profile M. The other rows are M-profile architectures, and a
 * profile other than M contradicts them.
 */
export const ARM_ELF_M_PROFILE_ARCHITECTURES = [
  { cpuArch: 11, label: "ARMv6-M", variant: "armv6-m" },
  { cpuArch: 12, label: "ARMv6S-M", variant: "armv6-m" },
  {
    cpuArch: 10,
    label: "ARMv7",
    variant: "armv7-m",
    requiresMProfile: true,
  },
  { cpuArch: 13, label: "ARMv7E-M", variant: "armv7e-m" },
  { cpuArch: 16, label: "ARMv8-M Baseline", variant: "armv8-m.base" },
  { cpuArch: 17, label: "ARMv8-M Mainline", variant: "armv8-m.main" },
  { cpuArch: 21, label: "ARMv8.1-M Mainline", variant: "armv8.1-m.main" },
] as const satisfies readonly {
  readonly cpuArch: number;
  readonly label: string;
  readonly variant: ArchitectureVariant;
  readonly requiresMProfile?: true;
}[];

type MProfileArchitecture = (typeof ARM_ELF_M_PROFILE_ARCHITECTURES)[number];

/** What the file-scope declarations establish about the M profile. */
export type ArmElfMProfile =
  | {
      readonly kind: "m-profile";
      readonly variant: ArchitectureVariant;
      readonly architecture: MProfileArchitecture;
    }
  /** A declared architecture or profile outside the M profile. */
  | { readonly kind: "other-profile" }
  /** The M profile is neither established nor excluded. */
  | { readonly kind: "unknown"; readonly reason: string };

const profileName = (value: number): string =>
  value >= 0x41 && value <= 0x5a
    ? `profile ${String.fromCharCode(value)}`
    : `profile value ${value}`;

/** Interpret the declarations; this is the one place that maps them to a variant. */
export const armElfMProfile = (
  attributes: ArmBuildAttributes,
): ArmElfMProfile => {
  const { cpuArch, cpuArchProfile } = attributes;
  const declaresM = cpuArchProfile === ARM_CPU_ARCH_PROFILE_M;
  const row = ARM_ELF_M_PROFILE_ARCHITECTURES.find(
    (candidate) => candidate.cpuArch === cpuArch,
  );
  if (cpuArch === null)
    return declaresM
      ? {
          kind: "unknown",
          reason: "Tag_CPU_arch_profile declares M without Tag_CPU_arch",
        }
      : cpuArchProfile === null
        ? {
            kind: "unknown",
            reason:
              "the attributes declare neither Tag_CPU_arch nor Tag_CPU_arch_profile",
          }
        : { kind: "other-profile" };
  if (row === undefined)
    return declaresM
      ? {
          kind: "unknown",
          reason: `Tag_CPU_arch ${cpuArch} with profile M has no M-profile variant`,
        }
      : { kind: "other-profile" };
  if ("requiresMProfile" in row)
    return declaresM
      ? { kind: "m-profile", variant: row.variant, architecture: row }
      : cpuArchProfile === null
        ? {
            kind: "unknown",
            reason: `${row.label} (Tag_CPU_arch ${cpuArch}) is declared without Tag_CPU_arch_profile`,
          }
        : { kind: "other-profile" };
  if (cpuArchProfile !== null && !declaresM)
    return {
      kind: "unknown",
      reason: `${row.label} (Tag_CPU_arch ${cpuArch}) contradicts ${profileName(cpuArchProfile)}`,
    };
  return { kind: "m-profile", variant: row.variant, architecture: row };
};

/** ELF header flags of EABI version 5 that declare the floating-point convention. */
export const EF_ARM_EABI_MASK = 0xff000000;
export const EF_ARM_EABI_VER5 = 0x05000000;
export const EF_ARM_ABI_FLOAT_SOFT = 0x00000200;
export const EF_ARM_ABI_FLOAT_HARD = 0x00000400;
export const EF_ARM_BE8 = 0x00800000;

/**
 * How an ARM ELF declares that floating-point arguments and results pass:
 * - `vfp`: in VFP registers (AAPCS-VFP, built with `-mfloat-abi=hard`);
 * - `base`: in core registers (base AAPCS, `-mfloat-abi=soft` or `softfp`);
 * - `compatible`: no floating-point value crosses a non-variadic interface;
 * - `toolchain`: a toolchain-specific convention;
 * - `unresolved`: the declarations disagree or use a reserved value;
 * - `undeclared`: neither the header nor the attributes declare one.
 */
export const ARM_ELF_FLOAT_ABIS = [
  "vfp",
  "base",
  "compatible",
  "toolchain",
  "unresolved",
  "undeclared",
] as const;
export type ArmElfFloatAbi = (typeof ARM_ELF_FLOAT_ABIS)[number];

const VFP_ARGS: Readonly<Record<number, ArmElfFloatAbi>> = {
  0: "base",
  1: "vfp",
  2: "toolchain",
  3: "compatible",
};

/**
 * The header's EABI5 float flags are a whole-image fact: linkers derive them
 * from every input. LLD keeps the first input's attributes section, so
 * Tag_ABI_VFP_args decides only when the header declares nothing. An
 * attribute that names the other convention leaves the declaration unresolved.
 */
export const armElfFloatAbi = (
  flags: number,
  vfpArgs: number | null,
): ArmElfFloatAbi => {
  const eabi5 = (flags & EF_ARM_EABI_MASK) >>> 0 === EF_ARM_EABI_VER5;
  const soft = eabi5 && (flags & EF_ARM_ABI_FLOAT_SOFT) !== 0;
  const hard = eabi5 && (flags & EF_ARM_ABI_FLOAT_HARD) !== 0;
  const attribute =
    vfpArgs === null ? undefined : (VFP_ARGS[vfpArgs] ?? "unresolved");
  if (soft && hard) return "unresolved";
  const header = hard ? "vfp" : soft ? "base" : undefined;
  if (header === undefined) return attribute ?? "undeclared";
  return attribute === undefined ||
    attribute === header ||
    attribute === "compatible"
    ? header
    : "unresolved";
};
