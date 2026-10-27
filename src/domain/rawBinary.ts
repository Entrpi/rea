import { z } from "zod";

import type {
  BinaryArchitecture,
  HeaderArchitecture,
  RawBinaryLoad,
  RawOnlyArchitecture,
} from "./binaryTargetTypes.js";
import type { ExecutableFormatHint } from "./dosCom.js";
import {
  rawArchitectureVariantRow,
  type RawArchitectureVariant,
} from "./rawArchitectureVariant.js";
import { err, ok, type Result } from "./result.js";

/** Caller-visible CPU families admitted for headerless raw binaries. */
export const BINARY_ARCHITECTURES = [
  "x86",
  "x86_64",
  "arm",
  "arm64",
  "6502",
  "m68k",
] as const satisfies readonly BinaryArchitecture[];

/** Provider-neutral CPU family for a caller-supplied raw-binary load. */
export const binaryArchitectureSchema = z.enum(BINARY_ARCHITECTURES);

const RAW_BINARY_ENTRY_POINT = /^0x[0-9A-Fa-f]{1,16}$/u;

/** Hexadecimal load and entry address; file offset 0 is mapped here. */
export const rawBinaryEntryPointSchema = z
  .string()
  .regex(RAW_BINARY_ENTRY_POINT, {
    message: "entry_point must be a hexadecimal address of the form 0x…",
  });

/** Hexadecimal address of raw file offset 0 when it differs from the entry. */
export const rawBinaryBaseAddressSchema = z
  .string()
  .regex(RAW_BINARY_ENTRY_POINT, {
    message: "base_address must be a hexadecimal address of the form 0x…",
  });

/** Hexadecimal address of an M-profile vector table inside the mapped image. */
export const rawBinaryVectorTableAddressSchema = z
  .string()
  .regex(RAW_BINARY_ENTRY_POINT, {
    message:
      "vector_table_address must be a hexadecimal address of the form 0x…",
  });

/** Canonicalized caller-supplied raw-binary entry with the original spelling. */
export interface CanonicalRawBinaryEntry {
  readonly source: string;
  readonly canonical: string;
  readonly value: bigint;
}

/** Parse a caller-supplied hex entry while preserving the source spelling. */
export const parseRawBinaryEntryPoint = (
  value: string,
): Result<CanonicalRawBinaryEntry, string> => {
  if (!RAW_BINARY_ENTRY_POINT.test(value))
    return err("entry_point must be a hexadecimal address of the form 0x…");
  const parsed = BigInt(value);
  return ok({
    source: value,
    canonical: `0x${parsed.toString(16)}`,
    value: parsed,
  });
};

/** Reject empty or non-integral file extents for a headerless image. */
export const validateRawBinaryLength = (
  length: number,
): Result<null, string> =>
  Number.isSafeInteger(length) && length >= 1
    ? ok(null)
    : err("raw-binary requires at least one file byte");

/**
 * Caller-selected interpretation that target headers do not establish. The
 * CLI and MCP boundaries build it once; it reaches target admission unchanged.
 */
export interface NativeLoadSelection {
  readonly format?: ExecutableFormatHint;
  readonly architecture?: BinaryArchitecture;
  readonly entryPoint?: string;
  readonly baseAddress?: string;
  readonly architectureVariant?: RawArchitectureVariant;
  readonly vectorTableAddress?: string;
}

/** Admitted headerless load identity used by target resolution and profiles. */
export interface RawBinaryAdmission {
  readonly architecture: HeaderArchitecture | RawOnlyArchitecture;
  readonly load: RawBinaryLoad;
}

/** Why a headerless load was refused, with its owning classification. */
export interface RawBinaryAdmissionRejection {
  readonly reason: string;
  /**
   * `load_selection_rejected` names a caller-input selection problem;
   * `file_format_rejected` names a refusal caused by the target file itself.
   */
  readonly constraint: "load_selection_rejected" | "file_format_rejected";
}

const addressWidth = (architecture: BinaryArchitecture): bigint =>
  architecture === "6502"
    ? 0xffffn
    : architecture === "x86" ||
        architecture === "arm" ||
        architecture === "m68k"
      ? 0xffffffffn
      : 0xffffffffffffffffn;

/** Validate architecture, entry, and that the mapped image fits the CPU width. */
export const admitRawBinary = (input: {
  readonly architecture: unknown;
  readonly entryPoint: unknown;
  readonly baseAddress?: unknown;
  readonly architectureVariant?: unknown;
  readonly vectorTableAddress?: unknown;
  readonly fileBytes: number;
}): Result<RawBinaryAdmission, RawBinaryAdmissionRejection> => {
  if (
    input.baseAddress !== undefined ||
    input.architectureVariant !== undefined ||
    input.vectorTableAddress !== undefined
  )
    return err({
      reason:
        "base_address, architecture_variant and vector_table_address are not admitted yet",
      constraint: "load_selection_rejected",
    });
  const architecture = binaryArchitectureSchema.safeParse(input.architecture);
  if (!architecture.success)
    return err({
      reason:
        "raw-binary format requires architecture (x86, x86_64, arm, arm64, 6502, or m68k)",
      constraint: "load_selection_rejected",
    });
  if (typeof input.entryPoint !== "string")
    return err({
      reason:
        "raw-binary format requires entry_point as a hexadecimal address of the form 0x…",
      constraint: "load_selection_rejected",
    });
  const entry = parseRawBinaryEntryPoint(input.entryPoint);
  if (!entry.ok)
    return err({
      reason: entry.error,
      constraint: "load_selection_rejected",
    });
  if (
    (architecture.data === "arm" || architecture.data === "arm64") &&
    entry.value.value % 4n !== 0n
  )
    return err({
      reason: `raw-binary ${architecture.data} entry_point ${entry.value.canonical} must be 4-byte aligned`,
      constraint: "load_selection_rejected",
    });
  // 68000-family instruction words are fetched from even addresses.
  if (architecture.data === "m68k" && entry.value.value % 2n !== 0n)
    return err({
      reason: `raw-binary m68k entry_point ${entry.value.canonical} must be 2-byte aligned`,
      constraint: "load_selection_rejected",
    });
  const length = validateRawBinaryLength(input.fileBytes);
  if (!length.ok)
    return err({
      reason: length.error,
      constraint: "file_format_rejected",
    });
  const last = entry.value.value + BigInt(input.fileBytes) - 1n;
  const max = addressWidth(architecture.data);
  if (entry.value.value > max || last > max)
    return err({
      reason: `raw-binary mapping from ${entry.value.canonical} must fit in the ${architecture.data} address width`,
      constraint: "load_selection_rejected",
    });
  return ok({
    architecture: architecture.data,
    // File offset 0 maps at the entry; no other base can be selected.
    load: {
      baseAddress: entry.value.canonical,
      entryPoint: entry.value.canonical,
      entryPointSource: entry.value.source,
    },
  });
};

/** A load selection refused before any file is read, naming the input to correct. */
export interface LoadSelectionIssue {
  readonly field:
    | "architecture"
    | "entry_point"
    | "base_address"
    | "architecture_variant"
    | "vector_table_address";
  readonly message: string;
}

const RAW_ONLY_INPUTS =
  "base_address, architecture_variant and vector_table_address apply only with format=raw-binary";

/**
 * Rules for the variant, base and vector-table inputs of a raw-binary
 * selection. The boundary pairing check and admission both apply them, so they
 * refuse the same selections in the same words. Legacy selections pass.
 */
export const rawBinaryVariantSelectionIssue = (input: {
  readonly architecture?: unknown;
  readonly entryPoint?: unknown;
  readonly baseAddress?: unknown;
  readonly architectureVariant?: unknown;
  readonly vectorTableAddress?: unknown;
}): LoadSelectionIssue | undefined => {
  const variant = rawArchitectureVariantRow(input.architectureVariant);
  if (variant !== undefined && variant.architecture !== input.architecture)
    return {
      field: "architecture_variant",
      message: `architecture_variant ${variant.name} requires architecture ${variant.architecture}`,
    };
  // Narrow first: only the M-profile lane is verified with a separate base.
  if (
    input.baseAddress !== undefined &&
    input.architectureVariant === undefined
  )
    return {
      field: "base_address",
      message: "base_address applies only with architecture_variant",
    };
  if (input.entryPoint !== undefined)
    return input.vectorTableAddress === undefined
      ? undefined
      : {
          field: "vector_table_address",
          message:
            "vector_table_address locates Reset only when entry_point is omitted",
        };
  if (
    input.baseAddress === undefined &&
    input.architectureVariant === undefined &&
    input.vectorTableAddress === undefined
  )
    return undefined;
  return input.architectureVariant !== undefined &&
    input.baseAddress !== undefined
    ? undefined
    : {
        field: "entry_point",
        message:
          "entry_point may be omitted only with architecture_variant and base_address; Reset is then read from the vector table",
      };
};

/** Describe the pairing of the selected load inputs without performing I/O. */
export const rawBinarySelectionError = (input: {
  readonly format?: ExecutableFormatHint;
  readonly architecture?: unknown;
  readonly entryPoint?: unknown;
  readonly baseAddress?: unknown;
  readonly architectureVariant?: unknown;
  readonly vectorTableAddress?: unknown;
}): LoadSelectionIssue | undefined => {
  const hasArchitecture = input.architecture !== undefined;
  const hasEntry = input.entryPoint !== undefined;
  const hasBase = input.baseAddress !== undefined;
  const hasVariant = input.architectureVariant !== undefined;
  const hasVectorTable = input.vectorTableAddress !== undefined;
  const rawOnlyField = hasBase
    ? "base_address"
    : hasVariant
      ? "architecture_variant"
      : hasVectorTable
        ? "vector_table_address"
        : undefined;
  if (input.format === "gamecube-dol") {
    // The DOL header fixes architecture; entry_point is checked against it at admission.
    if (hasArchitecture)
      return {
        field: "architecture",
        message:
          "format=gamecube-dol takes its architecture from the DOL header; omit architecture",
      };
    return rawOnlyField === undefined
      ? undefined
      : { field: rawOnlyField, message: RAW_ONLY_INPUTS };
  }
  if (input.format === "raw-binary") {
    if (!hasArchitecture)
      return {
        field: "architecture",
        message:
          rawOnlyField === undefined
            ? "format=raw-binary requires architecture and entry_point"
            : "format=raw-binary requires architecture",
      };
    const issue = rawBinaryVariantSelectionIssue(input);
    if (issue !== undefined) return issue;
    return hasEntry || rawOnlyField !== undefined
      ? undefined
      : {
          field: "entry_point",
          message: "format=raw-binary requires architecture and entry_point",
        };
  }
  if (hasArchitecture || hasEntry)
    return {
      field: hasArchitecture ? "architecture" : "entry_point",
      message: "architecture and entry_point apply only with format=raw-binary",
    };
  return rawOnlyField === undefined
    ? undefined
    : { field: rawOnlyField, message: RAW_ONLY_INPUTS };
};
