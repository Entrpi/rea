import { z } from "zod";
import { prefixedDigestSchema } from "./digests.js";
import { evidenceSchema } from "./evidence.js";
import { absoluteLocalPathStringSchema } from "./localPath.js";

/** Exact reference to Evidence already retained by the current session. */
export const retainedEvidenceReferenceSchema = z.strictObject({
  kind: z.literal("retained-evidence"),
  evidence_id: prefixedDigestSchema("ev"),
});

/** One completed Evidence record read from a local Evidence file or bundle. */
export const evidenceFileReferenceSchema = z.strictObject({
  kind: z.literal("evidence-file"),
  path: absoluteLocalPathStringSchema.describe(
    "Absolute local path of one completed Evidence JSON file, or of an Evidence bundle written by --evidence_output or export_evidence_bundle. REA reads and authenticates it, then uses it like retained Evidence, so large records are not charged as inline input.",
  ),
  evidence_id: prefixedDigestSchema("ev")
    .exactOptional()
    .describe(
      "The record to select when the file is an Evidence bundle, such as a summary's normalized_result.parent_evidence_id. A bundle holding exactly one record needs no selection.",
    ),
});
export type EvidenceFileReference = z.output<
  typeof evidenceFileReferenceSchema
>;

/** Evidence named instead of sent inline. Evidence itself is strict and has no kind. */
export const evidenceReferenceSchema = z.discriminatedUnion("kind", [
  retainedEvidenceReferenceSchema,
  evidenceFileReferenceSchema,
]);
export type EvidenceReference = z.output<typeof evidenceReferenceSchema>;

/** Portable observation or exact retained identity, for a loader that cannot read Evidence files. */
export const evidenceInputSchema = z.union([
  evidenceSchema,
  retainedEvidenceReferenceSchema,
]);
export type EvidenceInput = z.output<typeof evidenceInputSchema>;

/** Each Evidence source of a paired comparison or application workflow: inline, retained, or in a local Evidence file. */
export const evidenceSourceInputSchema = z.union([
  evidenceSchema,
  retainedEvidenceReferenceSchema,
  evidenceFileReferenceSchema,
]);
