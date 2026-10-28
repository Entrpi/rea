import { z } from "zod";
import { prefixedDigestSchema } from "./digests.js";
import { evidenceSchema, type Evidence } from "./evidence.js";
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

/** A key that Evidence does not have; the compiler rejects one Evidence gains. */
type NotEvidenceKey<Key extends string> = Key extends keyof Evidence
  ? never
  : Key;
const REFERENCE_DISCRIMINATOR: NotEvidenceKey<"kind"> = "kind";

/** Evidence named instead of sent inline: retained in the session or in a local Evidence file. */
export const evidenceReferenceSchema = z.discriminatedUnion(
  REFERENCE_DISCRIMINATOR,
  [retainedEvidenceReferenceSchema, evidenceFileReferenceSchema],
);
export type EvidenceReference = z.output<typeof evidenceReferenceSchema>;

/** Whether a source names a reference: Evidence is a strict object without the discriminator. */
export const namesEvidenceReference = (source: unknown): boolean =>
  typeof source === "object" &&
  source !== null &&
  Object.hasOwn(source, REFERENCE_DISCRIMINATOR);

/** Portable observation or exact retained identity, for a loader that cannot read Evidence files. */
export const evidenceInputSchema = z.union([
  evidenceSchema,
  retainedEvidenceReferenceSchema,
]);
export type EvidenceInput = z.output<typeof evidenceInputSchema>;

/** Every Evidence source form, as it is advertised. */
const evidenceSourceForms = z.union([
  evidenceSchema,
  ...evidenceReferenceSchema.options,
]);

/** Check a source only against the form namesEvidenceReference selects. */
const evidenceSourceParser = z
  .unknown()
  .nonoptional()
  .transform((source, context): z.output<typeof evidenceSourceForms> => {
    const parsed = namesEvidenceReference(source)
      ? evidenceReferenceSchema.safeParse(source)
      : evidenceSchema.safeParse(source);
    if (parsed.success) return parsed.data;
    for (const issue of parsed.error.issues)
      context.addIssue({ ...issue, path: [...issue.path] });
    return z.NEVER;
  });
// Zod clones reconstruct from the definition. Install the advertised forms in
// the constructor so a described source keeps them.
const EvidenceSource = z.core.$constructor<typeof evidenceSourceParser>(
  "EvidenceSource",
  (instance, definition) => {
    z.ZodPipe.init(instance, definition);
    instance._zod.processJSONSchema = (context, json, params) =>
      evidenceSourceForms._zod.processJSONSchema!(context, json, params);
  },
);

/**
 * Each Evidence source of a paired comparison or application workflow:
 * complete Evidence, a retained reference, or one record in a local Evidence
 * file. It is advertised as every form, but a malformed source reports only
 * the issues of the form it names.
 */
export const evidenceSourceInputSchema = new EvidenceSource(
  evidenceSourceParser._zod.def,
);

/** The request fields that name the two sides of a paired comparison. */
export const PAIRED_EVIDENCE_SOURCES = ["left", "right"] as const;

/** The request field that names an application workflow's Evidence. */
export const APPLICATION_EVIDENCE_SOURCE = ["application"] as const;

/** One Evidence source schema for each named request field. */
export const evidenceSourceShape = <const Field extends string>(
  fields: readonly Field[],
  description?: string,
): { readonly [Name in Field]: typeof evidenceSourceInputSchema } => {
  const source =
    description === undefined
      ? evidenceSourceInputSchema
      : evidenceSourceInputSchema.describe(description);
  return Object.fromEntries(fields.map((field) => [field, source])) as {
    readonly [Name in Field]: typeof evidenceSourceInputSchema;
  };
};
