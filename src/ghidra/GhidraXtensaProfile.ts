import { isDeepStrictEqual } from "node:util";

import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import type {
  BinaryTarget,
  XtensaAbiDeclaration,
  XtensaLiteralDeclaration,
} from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";

/**
 * Ghidra 12.1.4 `xtensa.ldefs` defines this language with a single compiler
 * specification, id `default` (`xtensa.cspec`); there is no `gcc` id. Its
 * default prototype models windowed calls; it also defines `__call0`.
 */
export const GHIDRA_XTENSA_LANGUAGE: GhidraLanguageOverride = {
  languageId: "Xtensa:LE:32:default",
  compilerSpecId: "default",
};

const ET_REL = 1;
const ET_EXEC = 2;
const ET_DYN = 3;

/** binutils `include/elf/xtensa.h`; `E_XTENSA_MACH` (0) is the only machine value. */
const EF_XTENSA_MACH = 0x0000000f;
const EF_XTENSA_XT_INSN = 0x00000100;
const EF_XTENSA_XT_LIT = 0x00000200;

/**
 * Bits this lane reads. Anything else in `e_flags` is refused rather than
 * assumed compatible.
 */
const EF_XTENSA_DECLARED_BITS =
  EF_XTENSA_MACH | EF_XTENSA_XT_INSN | EF_XTENSA_XT_LIT;

const abiUnsupportedReason = (
  abi: XtensaAbiDeclaration | undefined,
): string | null => {
  if (abi === undefined)
    return "The Xtensa ABI declaration in .xtensa.info was not inspected; this lane does not infer an ABI.";
  switch (abi.status) {
    case "declared":
      return null;
    case "unrecognized":
      return `The image declares ABI=${abi.value} in .xtensa.info, which binutils does not define; this lane admits only the windowed (0) and call0 (1) ABIs.`;
    case "absent":
      return "The image declares no ABI in .xtensa.info; this lane does not infer an ABI from the family name.";
    case "unavailable":
      return [
        "The Xtensa ABI declaration is unreadable or malformed, so this lane does not infer an ABI.",
        abi.reason,
      ].join(" ");
  }
};

/** Ghidra 12.1.4 computes every L32R address from the instruction's own address. */
const literalsUnsupportedReason = (
  literals: XtensaLiteralDeclaration | undefined,
): string | null => {
  if (literals === undefined)
    return "The Xtensa literal declaration in .xtensa.info was not inspected; this lane does not assume PC-relative L32R literals.";
  switch (literals.status) {
    case "declared":
      return literals.literals === "pc-relative"
        ? null
        : "The image declares USE_ABSOLUTE_LITERALS=1 in .xtensa.info: its configuration addresses L32R literals from LITBASE (the Extended L32R option). Ghidra 12.1.4 decodes every L32R as PC-relative, so literal loads and the references derived from them could be wrong; this lane admits only PC-relative literals (0), as ESP-IDF builds declare.";
    case "unrecognized":
      return `The image declares USE_ABSOLUTE_LITERALS=${literals.value} in .xtensa.info, which binutils does not define; this lane admits only PC-relative literals (0).`;
    case "absent":
      return "The image declares no USE_ABSOLUTE_LITERALS in .xtensa.info; this lane does not assume PC-relative L32R literals.";
    case "unavailable":
      return [
        "The Xtensa literal declaration is unreadable or malformed, so this lane does not assume PC-relative L32R literals.",
        literals.reason,
      ].join(" ");
  }
};

/** Keep family recognition separate from the deliberately bounded Ghidra lane. */
export const ghidraXtensaUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (target.kind !== "executable" || target.architecture !== "xtensa")
    return null;
  const metadata = target.xtensa;
  if (metadata.elfClass !== 32)
    return "This Ghidra Xtensa lane supports ELF32 only; Ghidra 12.1.4 ships 32-bit Xtensa languages only.";
  if (metadata.byteOrder !== "little")
    return "This Ghidra Xtensa lane supports little-endian images only; big-endian Xtensa cores need separate verification.";
  if (metadata.type !== ET_EXEC)
    return `This Ghidra Xtensa lane supports fixed-address ET_EXEC only; ${
      metadata.type === ET_REL
        ? "relocatable"
        : metadata.type === ET_DYN
          ? "shared and position-independent"
          : `e_type ${metadata.type}`
    } images need separate load verification.`;
  const unsupportedFlags = (metadata.flags & ~EF_XTENSA_DECLARED_BITS) >>> 0;
  if (unsupportedFlags !== 0)
    return `Xtensa e_flags declares bits outside the verified lane (0x${unsupportedFlags.toString(16)}); reserved or newer declarations are not treated as compatible with this profile.`;
  if ((metadata.flags & EF_XTENSA_MACH) !== 0)
    return `Xtensa e_flags declares machine ${metadata.flags & EF_XTENSA_MACH}; binutils defines only E_XTENSA_MACH (0), so this lane does not guess a core.`;
  return (
    abiUnsupportedReason(metadata.abi) ??
    literalsUnsupportedReason(metadata.literals)
  );
};

/** Prototype policy ReaGhidraXtensaCall0.java applies after analysis. */
export const GHIDRA_XTENSA_CALL0_PROTOTYPE = "call0-prototype-v1";

/** Whether the admitted target declares the call0 ABI in `.xtensa.info`. */
export const isGhidraXtensaCall0Target = (target: BinaryTarget): boolean =>
  target.kind === "executable" &&
  target.architecture === "xtensa" &&
  ghidraXtensaUnsupportedReason(target) === null &&
  target.xtensa.abi?.status === "declared" &&
  target.xtensa.abi.abi === "call0";

/** Prototype outcome the post-analysis script records for the bridge handshake. */
export interface GhidraXtensaCall0Report {
  readonly policy: typeof GHIDRA_XTENSA_CALL0_PROTOTYPE;
  readonly functions: number;
  readonly definitions: number;
}

/** Fail closed unless the call0 prototype ran exactly for call0 targets. */
export const ghidraXtensaCall0Failure = (
  expected: boolean,
  report: GhidraXtensaCall0Report | undefined,
): string | undefined =>
  expected === (report !== undefined)
    ? undefined
    : expected
      ? "The Ghidra session did not report the committed Xtensa call0 prototype."
      : "The Ghidra session reported an Xtensa call0 prototype that the profile did not commit.";

/** The prototype REA assigns, then the outcome the session reports. */
export const ghidraXtensaCall0Limitations = (
  expected: boolean,
  report?: GhidraXtensaCall0Report,
): readonly string[] =>
  expected
    ? [
        "Call0 ABI: Ghidra 12.1.4's default Xtensa prototype lists a8-a11, not a12-a15, as preserved across a call. After analysis REA assigns Ghidra's `__call0` prototype, which preserves a12-a15, to every function, external function and function definition, so calls to them have call0 register effects.",
        ...(report === undefined
          ? []
          : [
              `Call0 prototype outcome: ${report.functions} functions and ${report.definitions} function definitions use __call0.`,
            ]),
      ]
    : [];

/** Pin the language only for declarations admitted by the same lane boundary. */
export const ghidraXtensaLanguage = (
  target: BinaryTarget,
): GhidraLanguageOverride | undefined =>
  target.kind === "executable" &&
  target.architecture === "xtensa" &&
  ghidraXtensaUnsupportedReason(target) === null
    ? GHIDRA_XTENSA_LANGUAGE
    : undefined;

/** Commit source ELF interpretation without confusing target ISA with host CPU. */
export const ghidraXtensaProfileParameters = (
  target: BinaryTarget,
): Readonly<Record<string, JsonValue>> => {
  if (target.kind !== "executable" || target.architecture !== "xtensa")
    return {};
  const { elfClass, byteOrder, type, flags, abi, literals } = target.xtensa;
  const call0 = isGhidraXtensaCall0Target(target);
  return {
    xtensa_elf: {
      elf_class: elfClass,
      byte_order: byteOrder,
      type,
      flags,
      abi: abi?.status === "declared" ? abi.abi : null,
      literals: literals?.status === "declared" ? literals.literals : null,
    },
    xtensa_support_lane: call0
      ? "elf32-le-exec-call0-generic-v1"
      : "elf32-le-exec-windowed-generic-v1",
    ...(call0 ? { xtensa_call0_prototype: GHIDRA_XTENSA_CALL0_PROTOTYPE } : {}),
  };
};

/**
 * Bind a committed Xtensa profile to the target being imported. Every admitted
 * Xtensa ELF pins the same language, so the language checks alone cannot tell
 * a profile resolved for another image, whose ELF facts every Evidence record
 * would then attribute to this one.
 */
export const ghidraXtensaProfileMismatchReason = (
  target: BinaryTarget,
  parameters: Readonly<Record<string, unknown>>,
): string | null => {
  const expected = ghidraXtensaProfileParameters(target);
  return isDeepStrictEqual(parameters.xtensa_elf, expected.xtensa_elf) &&
    parameters.xtensa_support_lane === expected.xtensa_support_lane
    ? null
    : "The committed Xtensa analysis profile was resolved for a different target; reopen the target to resolve a new profile.";
};

/** What verify:ghidra:xtensa and REA's ESP-IDF measurement establish, and what they do not. */
export const ghidraXtensaLimitations = (
  target: BinaryTarget,
): readonly string[] => {
  if (target.kind !== "executable" || target.architecture !== "xtensa")
    return [];
  if (!isGhidraXtensaCall0Target(target))
    return [
      "REA verifies this lane against Ghidra 12.1.4 with source-owned windowed-call fixtures (entry, call8, retw.n, l32r). Decompiled code for other images is not verified function by function; check call targets and arguments against the assembly when they matter.",
      "REA pins Ghidra's generic `Xtensa:LE:32:default` language with the `default` compiler specification, whose default prototype models windowed calls according to Ghidra 12.1.4's xtensa.cspec. The language does not identify the ESP32, ESP32-S2 or ESP32-S3 core configuration or the producing compiler.",
      "Measured by REA: Ghidra 12.1.4 does not decode SALT/SALTU, which ESP32-S3 builds use, so disassembly, calls and parameters after them are missing in that function. Reported upstream or derived from Ghidra 12.1.4 sources, not reproduced by REA: decompiled output approximates register-window rotation; FLIX bundles and ESP32-S3 `ee.*` vector instructions are not decoded; zero-overhead loops are mis-modeled.",
    ];
  return [
    "REA verifies this lane against Ghidra 12.1.4 with source-owned call0 fixtures (call0, callx0, ret.n, l32r, a value kept in a12 across a call) and call0 builds from xtensa-lx106-elf-gcc 13.3.0 and xtensa-esp32-elf-gcc -mabi=call0. Decompiled code for other images is not verified function by function; check call targets and arguments against the assembly when they matter.",
    "REA pins Ghidra's generic `Xtensa:LE:32:default` language with the `default` compiler specification. The language does not identify the ESP8266 or another core configuration, or the producing compiler.",
    "Measured by REA: a call to an address with no function in the program, such as an ESP8266 mask-ROM routine outside the image, keeps Ghidra's default prototype: a value kept in a12 across it is computed before the call. Derived from Ghidra 12.1.4 sources, not reproduced by REA: the default prototype does not preserve a12-a15 at such a call, the same applies to a call through an untyped function pointer, and auto-analysis ran with the default prototype before REA assigned `__call0`.",
    "Measured by REA: Ghidra 12.1.4 does not decode SALT/SALTU, so disassembly, calls and parameters after them are missing in that function. Reported upstream or derived from Ghidra 12.1.4 sources, not reproduced by REA: FLIX bundles and ESP32-S3 `ee.*` vector instructions are not decoded; zero-overhead loops are mis-modeled.",
  ];
};
