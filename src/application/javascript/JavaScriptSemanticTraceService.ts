import { z } from "zod";

import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { APPLICATION_EVIDENCE_SOURCE } from "../../domain/evidenceReference.js";
import { parseAnalysisInput } from "../AnalysisInput.js";
import {
  resolveEvidenceSources,
  type EvidenceLookup,
} from "../EvidenceInputResolver.js";
import type { EvidenceFileReadOptions } from "../analysisView/evidenceFileSource.js";
import {
  applicationGraphEvidenceInputError,
  parseApplicationGraphEvidence,
} from "./JavaScriptApplicationEvidenceGraph.js";
import type { ApplicationWorkflowExecution } from "./JavaScriptApplicationWorkflowService.js";
import { queryJavaScriptSemanticGraph } from "../../domain/javascript/javascriptSemanticQuery.js";
import {
  traceJavaScriptSemanticsInputSchema,
  type JavaScriptSemanticTraceResult,
} from "../../domain/javascript/javascriptSemanticTraceSchemas.js";
import { err, ok, type Result } from "../../domain/result.js";
import { createJavaScriptSemanticTraceEvidence } from "./JavaScriptApplicationWorkflowEvidence.js";

const OPERATION = "trace_javascript_semantics" as const;

// Validate the request frame without cloning the application payload before its owner reads it.
const semanticTraceFrameSchema = z.strictObject({
  ...traceJavaScriptSemanticsInputSchema.shape,
  application: z.unknown().nonoptional(),
});

/** Resolve the application Evidence, then trace bounded static semantic relations through it. */
export const traceJavaScriptSemanticsEvidence = async (
  rawInput: unknown,
  lookup?: EvidenceLookup,
  options: EvidenceFileReadOptions = {},
): Promise<
  Result<
    ApplicationWorkflowExecution<JavaScriptSemanticTraceResult>,
    AnalysisError
  >
> => {
  const request = parseAnalysisInput(
    OPERATION,
    rawInput,
    semanticTraceFrameSchema,
    options.signal,
  );
  if (!request.ok) return request;
  const selected = await resolveEvidenceSources(
    request.value,
    APPLICATION_EVIDENCE_SOURCE,
    lookup,
    { ...options, operation: OPERATION },
  );
  if (!selected.ok) return selected;
  const input = selected.value;
  const sourceResult = parseApplicationGraphEvidence(input.application, [
    "application",
  ]);
  if (!sourceResult.ok)
    return err(
      applicationGraphEvidenceInputError(OPERATION, sourceResult.error),
    );
  const source = sourceResult.value;
  if (source.semanticGraph === null)
    return err(
      new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["application"],
          reason: "invalid_value",
          expected:
            "analyze_javascript_application Evidence with a semantic graph",
        },
      ]),
    );
  const query = queryJavaScriptSemanticGraph(source.semanticGraph, input.query);
  const result: JavaScriptSemanticTraceResult = {
    ...query,
    source_evidence_id: source.evidence.evidence_id,
    evidence_links: [source.evidence.evidence_id],
  };
  const { allowed_relations, ...queryParameters } = input.query;
  const evidence = createJavaScriptSemanticTraceEvidence(
    {
      application_evidence_id: source.evidence.evidence_id,
      query:
        allowed_relations === undefined
          ? queryParameters
          : { ...queryParameters, allowed_relations },
    },
    result,
  );
  return ok({ evidence, result, sources: [source.evidence] });
};
