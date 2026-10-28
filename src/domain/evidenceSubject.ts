import { z } from "zod";

import {
  BINARY_ARCHITECTURES,
  RAW_ONLY_ARCHITECTURES,
} from "./binaryTargetTypes.js";
import {
  DECLARED_ARCHITECTURE_ROWS,
  TARGET_FORMAT_IDS,
} from "./targetFormats.js";

export const evidenceSubjectFormatSchema = z.enum(TARGET_FORMAT_IDS);

/** Format-owned architecture declarations shared by Evidence and persisted executions. */
const detectedEvidenceSubjectDeclaration = {
  format: evidenceSubjectFormatSchema.exclude(
    DECLARED_ARCHITECTURE_ROWS.map((row) => row.id),
  ),
  architecture: z
    .enum(BINARY_ARCHITECTURES)
    .exclude([...RAW_ONLY_ARCHITECTURES])
    .nullable(),
};

const declaredEvidenceSubjectDeclarations = DECLARED_ARCHITECTURE_ROWS.map(
  (row) => ({
    format: z.literal(row.id),
    architecture:
      row.architecture === "caller-selected"
        ? z.enum(BINARY_ARCHITECTURES).nullable()
        : z.literal(row.architecture.fixed),
  }),
);

/** Add the complete format-owned declaration to a persistence envelope. */
export const withEvidenceSubjectDeclaration = <
  Shape extends z.ZodRawShape,
  Config extends z.core.$ZodObjectConfig,
>(
  base: z.ZodObject<Shape, Config>,
) =>
  z.discriminatedUnion("format", [
    base.extend(detectedEvidenceSubjectDeclaration),
    ...declaredEvidenceSubjectDeclarations.map((declaration) =>
      base.extend(declaration),
    ),
  ]);
