import {
  executableFormatHintSchema,
  type ExecutableFormatHint,
} from "../domain/dosCom.js";
import { absoluteLocalPathStringSchema } from "../domain/localPath.js";
import {
  binaryArchitectureSchema,
  rawBinaryEntryPointSchema,
  rawBinarySelectionError,
  type NativeLoadSelection,
} from "../domain/rawBinary.js";
import { z } from "zod";
import { analysisProviderSelectorSchema } from "../domain/providerSelection.js";

/** Caller-supplied analysis snapshot path; must name its destination absolutely. */
const snapshotPathSchema = absoluteLocalPathStringSchema.describe(
  "Absolute local filesystem path for the analysis snapshot; relative paths are rejected.",
);

/** Caller-supplied analysis target path; must name the target absolutely. */
const binaryTargetPathSchema = absoluteLocalPathStringSchema.describe(
  "Absolute local filesystem path for the analysis target; relative paths are rejected.",
);

/** Collect the open_binary load fields into the selection that target admission owns. */
export const openBinaryLoadSelection = (input: {
  readonly format?: ExecutableFormatHint | undefined;
  readonly architecture?: NativeLoadSelection["architecture"] | undefined;
  readonly entry_point?: string | undefined;
}): NativeLoadSelection => ({
  ...(input.format === undefined ? {} : { format: input.format }),
  ...(input.architecture === undefined
    ? {}
    : { architecture: input.architecture }),
  ...(input.entry_point === undefined ? {} : { entryPoint: input.entry_point }),
});

/** Input contract for opening a target with an optional staged snapshot. */
export const openBinaryInputSchema = z
  .strictObject({
    path: binaryTargetPathSchema,
    format: executableFormatHintSchema
      .optional()
      .describe(
        "Explicit interpretation: dos-com or raw-binary (headerless), or gamecube-dol (GameCube/Wii DOL, never auto-detected). Omission preserves header-based detection.",
      ),
    architecture: binaryArchitectureSchema
      .optional()
      .describe(
        "Caller-supplied CPU family. Required with format=raw-binary; rejected otherwise. format=gamecube-dol takes powerpc from the header, so it must be omitted.",
      ),
    entry_point: rawBinaryEntryPointSchema
      .optional()
      .describe(
        "Caller-supplied load and entry address (0xhex). File offset 0 is mapped here. Required with format=raw-binary; rejected otherwise. Optional with format=gamecube-dol; must equal the DOL header entry.",
      ),
    provider_id: analysisProviderSelectorSchema.optional(),
    snapshot_path: snapshotPathSchema.optional(),
  })
  .superRefine((value, context) => {
    const pairing = rawBinarySelectionError(openBinaryLoadSelection(value));
    if (pairing === undefined) return;
    context.addIssue({
      code: "custom",
      path:
        value.format === "raw-binary"
          ? value.architecture === undefined
            ? ["architecture"]
            : ["entry_point"]
          : value.architecture === undefined
            ? ["entry_point"]
            : ["architecture"],
      message: pairing,
    });
  });

/** Open only app resources when no declared executable is available. */
export const openBundleResourcesInputSchema = z.strictObject({
  path: binaryTargetPathSchema,
});

/** Input contract for closing a target after an optional atomic snapshot. */
export const closeBinaryInputSchema = z.strictObject({
  snapshot_path: snapshotPathSchema.optional(),
  overwrite: z.boolean().default(false),
});
