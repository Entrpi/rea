import { z } from "zod";

import {
  BINARY_ARCHITECTURES,
  ELF_METADATA_ARCHITECTURES,
  RAW_ONLY_ARCHITECTURES,
} from "./binaryTargetTypes.js";
import { digestSchema } from "./digests.js";
import {
  binaryArchitectureSchema,
  rawBinaryEntryPointSchema,
} from "./rawBinary.js";
import {
  DECLARED_ARCHITECTURE_ROWS,
  inPublishedOrder,
  TARGET_KINDS,
  targetFormatIds,
  targetFormatSchema,
  type HeaderArchitectureRule,
  type TargetKind,
} from "./targetFormats.js";

const architectureSchema = z.enum(BINARY_ARCHITECTURES);
const headerArchitectureSchema = architectureSchema.exclude([
  ...ELF_METADATA_ARCHITECTURES,
  ...RAW_ONLY_ARCHITECTURES,
  "hexagon",
  "arm64_32",
]);
const identity = { path: z.string(), sha256: digestSchema };
const executable = { ...identity, kind: z.literal("executable") };

/** Families currently admitted for each header rule. */
const headerArchitectures = {
  elf: architectureSchema.exclude([...RAW_ONLY_ARCHITECTURES, "arm64_32"]),
  "mach-o": z.enum([...headerArchitectureSchema.options, "arm64_32"]),
  header: headerArchitectureSchema,
} satisfies Record<HeaderArchitectureRule, z.ZodType>;

/** Order published before the format table; later header executables follow. */
const PUBLISHED_HEADER_FORMATS = [
  "mach-o-universal",
  "pe",
  "dos-mz",
  "dos-com",
] as const;

const headerVariant = (rule: HeaderArchitectureRule) =>
  z.object({
    ...executable,
    format: targetFormatSchema(
      inPublishedOrder(
        targetFormatIds("architecture", rule),
        PUBLISHED_HEADER_FORMATS,
      ),
    ),
    architecture: headerArchitectures[rule],
  });

const nonExecutableKinds = TARGET_KINDS.filter(
  (kind): kind is Exclude<TargetKind, "executable"> => kind !== "executable",
);

/** Live target classifications; historical Evidence and snapshots retain their own admission. */
export const liveBinaryTargetSummaryVariants = [
  headerVariant("elf"),
  headerVariant("mach-o"),
  headerVariant("header"),
  ...DECLARED_ARCHITECTURE_ROWS.map((row) =>
    z.object({
      ...executable,
      format: z.literal(row.id),
      architecture:
        row.architecture === "caller-selected"
          ? binaryArchitectureSchema
          : z.literal(row.architecture.fixed),
      entry_point: rawBinaryEntryPointSchema.describe(row.entryPoint),
    }),
  ),
  ...nonExecutableKinds.map((kind) =>
    z.object({
      ...identity,
      kind: z.literal(kind),
      format: targetFormatSchema(targetFormatIds("target", kind)),
      architecture: z.null(),
    }),
  ),
] as const;

/** Exact wire projection of the currently admitted canonical target variants. */
export const liveBinaryTargetSummarySchema = z.discriminatedUnion(
  "format",
  liveBinaryTargetSummaryVariants,
);
