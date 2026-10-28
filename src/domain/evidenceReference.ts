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

/** The references a source can name, in their union order after inline Evidence. */
const SOURCE_REFERENCES = [
  retainedEvidenceReferenceSchema,
  evidenceFileReferenceSchema,
] as const;
const SOURCE_REFERENCE_KINDS = SOURCE_REFERENCES.map(
  (reference) => reference.shape.kind.value,
);

const formatSourceIssue = ({ path, message }: z.core.$ZodIssue): string =>
  path.length === 0 ? message : `${path.map(String).join(".")}: ${message}`;

/**
 * Standard Schema clients, such as the MCP SDK, show a failed union's message
 * but not its branch issues. Evidence has no kind and each reference has one,
 * so report the issues of the form that the source's own kind selects.
 */
const sourceFormIssues = (issue: z.core.$ZodRawIssue): string | undefined => {
  if (issue.code !== "invalid_union") return undefined;
  const { input } = issue;
  const named =
    typeof input === "object" && input !== null && Object.hasOwn(input, "kind");
  // Form 0 is inline Evidence; each reference follows in its union order.
  const form = named
    ? SOURCE_REFERENCE_KINDS.indexOf(Reflect.get(input, "kind")) + 1
    : 0;
  if (named && form === 0)
    return `kind: Invalid input: expected ${SOURCE_REFERENCE_KINDS.map((kind) => JSON.stringify(kind)).join(" or ")}; complete Evidence has no kind`;
  const issues = issue.errors[form];
  return issues === undefined || issues.length === 0
    ? undefined
    : issues.map(formatSourceIssue).join(", ");
};

/** Each Evidence source of a paired comparison or application workflow: inline, retained, or in a local Evidence file. */
export const evidenceSourceInputSchema = z.union(
  [evidenceSchema, ...SOURCE_REFERENCES],
  { error: sourceFormIssues },
);
