import {
  absoluteLocalPathStringSchema,
  localPathStringSchema,
} from "../../domain/localPath.js";
import { sourceToBundleViewRequestSchema } from "../../domain/analysisView/sourceToBundleView.js";
import { z } from "zod";

import {
  APPLICATION_EVIDENCE_SOURCE,
  PAIRED_EVIDENCE_SOURCES,
  evidenceSourceShape,
} from "../../domain/evidenceReference.js";
import { compareApplicationVersionsInputSchema } from "../../domain/javascript/javascriptApplicationVersionComparisonSchemas.js";
import { compareJavaScriptExportShapesInputSchema } from "../../domain/javascript/javascriptExportShapeComparisonSchemas.js";
import { traceApplicationFeatureInputSchema } from "../../domain/javascript/javascriptFeatureTraceSchemas.js";
import { javaScriptSemanticQueryInputSchema } from "../../domain/javascript/javascriptSemanticQuerySchemas.js";
import { compareSourceToBundleInputSchema } from "../../domain/javascript/sourceToBundleComparisonSchemas.js";

const traceApplicationFeatureFacts = {
  native_observations:
    traceApplicationFeatureInputSchema.shape.native_observations,
  seed: traceApplicationFeatureInputSchema.shape.seed,
  semantic_page: traceApplicationFeatureInputSchema.shape.semantic_page,
  direction: traceApplicationFeatureInputSchema.shape.direction,
} as const;

/** Application trace request; the application Evidence is inline, retained, or in an Evidence file. */
export const traceApplicationFeatureRequestSchema = z.strictObject({
  ...traceApplicationFeatureFacts,
  ...evidenceSourceShape(APPLICATION_EVIDENCE_SOURCE),
});

/** Semantic trace request; the application Evidence is inline, retained, or in an Evidence file. */
export const traceJavaScriptSemanticsRequestSchema = z.strictObject({
  ...evidenceSourceShape(APPLICATION_EVIDENCE_SOURCE),
  query: javaScriptSemanticQueryInputSchema,
});

const compareApplicationVersionsFacts = {
  left_native_observations:
    compareApplicationVersionsInputSchema.shape.left_native_observations,
  right_native_observations:
    compareApplicationVersionsInputSchema.shape.right_native_observations,
} as const;

/** Application comparison request; each side is inline, retained, or in an Evidence file. */
export const compareApplicationVersionsRequestSchema = z.strictObject({
  ...compareApplicationVersionsFacts,
  ...evidenceSourceShape(PAIRED_EVIDENCE_SOURCES),
});

const referenceFile = z.strictObject({
  kind: z.literal("file"),
  path: localPathStringSchema,
});
const sourceToBundleSelection = {
  view: z
    .union([
      z.strictObject({ kind: z.literal("summary") }),
      sourceToBundleViewRequestSchema,
    ])
    .optional(),
};
/** Historical graph JSON is a transport alternative to the inline graph, authenticated by the same graph parser. */
export const compareSourceToBundleCliInputSchema = z.strictObject({
  reference: z.union([
    compareSourceToBundleInputSchema.shape.reference,
    referenceFile,
  ]),
  ...evidenceSourceShape(APPLICATION_EVIDENCE_SOURCE),
});
/** The MCP host accepts absolute local paths; omitted view preserves the full report. */
export const compareSourceToBundleRequestSchema = z.strictObject({
  reference: z.union([
    compareSourceToBundleInputSchema.shape.reference,
    referenceFile.extend({ path: absoluteLocalPathStringSchema }),
  ]),
  ...evidenceSourceShape(APPLICATION_EVIDENCE_SOURCE),
  ...sourceToBundleSelection,
});

const compareJavaScriptExportShapesFacts = {
  left_module_path:
    compareJavaScriptExportShapesInputSchema.shape.left_module_path,
  left_export_name:
    compareJavaScriptExportShapesInputSchema.shape.left_export_name,
  right_module_path:
    compareJavaScriptExportShapesInputSchema.shape.right_module_path,
  right_export_name:
    compareJavaScriptExportShapesInputSchema.shape.right_export_name,
} as const;

/** Export-shape request; each side is inline, retained, or in an Evidence file. */
export const compareJavaScriptExportShapesRequestSchema = z.strictObject({
  ...compareJavaScriptExportShapesFacts,
  ...evidenceSourceShape(PAIRED_EVIDENCE_SOURCES),
});
