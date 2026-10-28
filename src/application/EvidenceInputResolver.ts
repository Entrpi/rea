import {
  evidenceReferenceSchema,
  namesEvidenceReference,
  type EvidenceInput,
  type EvidenceReference,
} from "../domain/evidenceReference.js";
import type { Evidence } from "../domain/evidence.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { EvidenceReferenceError } from "../domain/evidenceErrors.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  readEvidenceFileSource,
  type EvidenceFileReadOptions,
} from "./analysisView/evidenceFileSource.js";

/** Read-only lookup supplied by the current investigation's Evidence ledger. */
export type EvidenceLookup = (evidenceId: string) => Evidence | undefined;

/** Normalize each selected record using its file context and the current ledger. */
export interface EvidenceSourceResolutionOptions<
  Field extends string = string,
> extends EvidenceFileReadOptions {
  readonly operation: string;
  /**
   * Receives each source once its reference resolves. Inline Evidence arrives
   * as supplied, before any authentication. A record selected from an
   * Evidence file looks up related records in that file before the ledger.
   */
  readonly resolveEvidence?: (
    source: unknown,
    lookup: EvidenceLookup | undefined,
    field: Field,
  ) => Result<Evidence, AnalysisError>;
}

/** Resolve an exact reference without selecting a target or running analysis. */
export const resolveEvidenceInput = (
  input: EvidenceInput,
  lookup: EvidenceLookup | undefined,
): Result<Evidence, EvidenceReferenceError> => {
  if (!("kind" in input)) return ok(input);
  const record = lookup?.(input.evidence_id);
  if (record === undefined)
    return err(
      new EvidenceReferenceError(
        input.evidence_id,
        "missing",
        "Evidence available to the selected source",
        null,
      ),
    );
  if (record.evidence_id !== input.evidence_id)
    return err(
      new EvidenceReferenceError(
        input.evidence_id,
        "identity_mismatch",
        input.evidence_id,
        record.evidence_id,
      ),
    );
  return ok(record);
};

/** A reference resolves to Evidence; inline Evidence is unchanged until its consumer authenticates it. */
type ResolvedEvidenceSource<Source> = Source extends EvidenceReference
  ? Evidence
  : Source;

/**
 * Resolve the named Evidence sources of one request, in order. A retained
 * reference resolves from the session and an Evidence file through the shared
 * reader; inline Evidence passes through unchanged for its consumer to
 * authenticate. A workflow can pass sources it has not parsed: inline Evidence
 * is then not copied, and a malformed reference is an input error at its field.
 */
export const resolveEvidenceSources = async <
  Request extends { readonly [Name in Field]: unknown },
  Field extends string,
>(
  request: Request,
  fields: readonly Field[],
  lookup: EvidenceLookup | undefined,
  options: EvidenceSourceResolutionOptions<Field>,
): Promise<
  Result<
    Omit<Request, Field> & {
      readonly [Name in Field]: ResolvedEvidenceSource<Request[Name]>;
    },
    AnalysisError
  >
> => {
  const resolved: Partial<Record<Field, unknown>> = {};
  for (const field of fields) {
    const source = await resolveEvidenceSource(request, field, lookup, options);
    if (!source.ok) return source;
    resolved[field] = source.value;
  }
  // Each named field now holds its resolved source; the others are unchanged.
  return ok({ ...request, ...resolved } as Omit<Request, Field> & {
    readonly [Name in Field]: ResolvedEvidenceSource<Request[Name]>;
  });
};

const resolveEvidenceSource = async <Field extends string>(
  request: { readonly [Name in Field]: unknown },
  field: Field,
  lookup: EvidenceLookup | undefined,
  options: EvidenceSourceResolutionOptions<Field>,
): Promise<Result<unknown, AnalysisError>> => {
  const { operation, resolveEvidence } = options;
  const source = request[field];
  if (!namesEvidenceReference(source))
    return resolveEvidence?.(source, lookup, field) ?? ok(source);
  const reference = evidenceReferenceSchema.safeParse(source);
  if (!reference.success)
    return err(
      analysisInputErrorFromIssues(
        operation,
        reference.error.issues.map((issue) => ({
          ...issue,
          path: [field, ...issue.path],
        })),
        request,
        { cause: reference.error },
      ),
    );
  if (reference.data.kind === "evidence-file")
    return readEvidenceFileSource(
      reference.data.path,
      options,
      reference.data.evidence_id,
      {
        operation,
        path: [field],
        resolveSelected: (selected, fileLookup) =>
          resolveEvidence?.(
            selected,
            (id) => fileLookup(id) ?? lookup?.(id),
            field,
          ) ?? ok(selected),
      },
    );
  const selected = resolveEvidenceInput(reference.data, lookup);
  return selected.ok
    ? (resolveEvidence?.(selected.value, lookup, field) ?? selected)
    : selected;
};
