import { Cli, z } from "incur";

import { CLI_COMMANDS } from "../cliCommandNames.js";
import { parseCliJsonInput } from "../cliJsonInput.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  APPLICATION_EVIDENCE_SOURCE,
  PAIRED_EVIDENCE_SOURCES,
} from "../domain/evidenceReference.js";
import { JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER } from "../domain/investigationProviders.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { ok } from "../domain/result.js";
import type { Logger } from "pino";
import { registerEvidenceSourceCommand } from "./evidenceSourceCommand.js";
import { registerSourceToBundleCommand } from "./sourceToBundleCommand.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";

type CliInstance = ReturnType<typeof Cli.create>;

/** Register CLI equivalents of provider-neutral application graph workflows. */
export const registerApplicationCommands = (
  cli: ReturnType<typeof Cli.create>,
  logger: Logger,
): void => {
  registerJavaScriptWorkflowCommands(cli, logger);
  registerObligationLedgerCommand(cli, logger);
  registerCoverageCommand(cli, logger);
  registerJsonCommand({
    cli,
    logger,
    name: CLI_COMMANDS.projectAndroidApplicationGraph,
    description:
      "Project authenticated APK inventory Evidence into an Android application graph",
    inputSchema: z.unknown(),
    workflow: async (input) => {
      const { projectAndroidApplicationEvidence } =
        await import("../application/android/AndroidApplicationService.js");
      const result = projectAndroidApplicationEvidence(input);
      return result.ok ? { ok: true, value: result.value.evidence } : result;
    },
  });
  registerJsonCommand({
    cli,
    logger,
    name: CLI_COMMANDS.projectAppleApplicationGraph,
    description:
      "Project authenticated IPA or macOS app inventory Evidence into an Apple application graph",
    inputSchema: z.unknown(),
    workflow: async (input) => {
      const { projectAppleApplicationEvidence } =
        await import("../application/apple/AppleApplicationService.js");
      const result = projectAppleApplicationEvidence(input);
      return result.ok ? { ok: true, value: result.value.evidence } : result;
    },
  });
  registerJsonCommand({
    cli,
    logger,
    name: CLI_COMMANDS.projectHarmonyApplicationGraph,
    description:
      "Project authenticated HarmonyOS HAP, HSP, or App Pack inventory Evidence into an application graph",
    inputSchema: z.unknown(),
    workflow: async (input) => {
      const { projectHarmonyApplicationEvidence } =
        await import("../application/harmony/HarmonyApplicationService.js");
      const result = projectHarmonyApplicationEvidence(input);
      return result.ok ? { ok: true, value: result.value.evidence } : result;
    },
  });
};

const registerObligationLedgerCommand = (
  cli: CliInstance,
  logger: Logger,
): void =>
  registerJsonCommand({
    cli,
    logger,
    name: CLI_COMMANDS.buildReconstructionObligationLedger,
    description:
      "Generate a deterministic Evidence-backed reconstruction obligation ledger page",
    inputSchema: z.unknown(),
    workflow: async (input) => {
      const { buildReconstructionObligationLedgerEvidence } =
        await import("../application/ReconstructionObligationLedgerService.js");
      return buildReconstructionObligationLedgerEvidence(input);
    },
  });

const registerCoverageCommand = (cli: CliInstance, logger: Logger): void =>
  registerJsonCommand({
    cli,
    logger,
    name: CLI_COMMANDS.evaluateReconstructionCoverage,
    description: "Evaluate inline fail-closed reconstruction coverage",
    inputSchema: z.unknown(),
    workflow: async (input) => {
      const { evaluateReconstructionCoverage } =
        await import("../application/ReconstructionCoverageService.js");
      return evaluateReconstructionCoverage(input);
    },
  });

/** JavaScript application workflows, whose Evidence sources can be saved files. */
const registerJavaScriptWorkflowCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const providerId = JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER.id;
  registerEvidenceSourceCommand(cli, logger, {
    name: CLI_COMMANDS.traceApplicationFeature,
    operation: "trace_application_feature",
    providerId,
    description:
      'Trace a typed seed through authenticated application Evidence, inline or {kind:"evidence-file",path,evidence_id?}',
    inputSchema: z.unknown(),
    sources: APPLICATION_EVIDENCE_SOURCE,
    workflow: async (input, options) => {
      const { traceApplicationFeatureEvidence } =
        await import("../application/javascript/JavaScriptApplicationWorkflowService.js");
      const result = await traceApplicationFeatureEvidence(
        input,
        undefined,
        options,
      );
      return result.ok ? ok(result.value.evidence) : result;
    },
  });
  registerEvidenceSourceCommand(cli, logger, {
    name: CLI_COMMANDS.traceJavaScriptSemantics,
    operation: "trace_javascript_semantics",
    providerId,
    description:
      'Trace bounded static semantic relations through authenticated application Evidence, inline or {kind:"evidence-file",path,evidence_id?}',
    inputSchema: z.unknown(),
    sources: APPLICATION_EVIDENCE_SOURCE,
    workflow: async (input, options) => {
      const { traceJavaScriptSemanticsEvidence } =
        await import("../application/javascript/JavaScriptSemanticTraceService.js");
      const result = await traceJavaScriptSemanticsEvidence(
        input,
        undefined,
        options,
      );
      return result.ok ? ok(result.value.evidence) : result;
    },
  });
  registerEvidenceSourceCommand(cli, logger, {
    name: CLI_COMMANDS.compareApplicationVersions,
    operation: "compare_application_versions",
    providerId,
    description:
      'Compare two authenticated JavaScript Application Graph versions, each inline or {kind:"evidence-file",path,evidence_id?}',
    inputSchema: z.unknown(),
    sources: PAIRED_EVIDENCE_SOURCES,
    workflow: async (input, options) => {
      const { compareApplicationVersionsEvidence } =
        await import("../application/javascript/JavaScriptApplicationWorkflowService.js");
      const result = await compareApplicationVersionsEvidence(
        input,
        undefined,
        options,
      );
      return result.ok ? ok(result.value.evidence) : result;
    },
  });
  registerSourceToBundleCommand(cli, logger);
  registerEvidenceSourceCommand(cli, logger, {
    name: CLI_COMMANDS.compareJavaScriptExportShapes,
    operation: "compare_javascript_export_shapes",
    providerId,
    description:
      'Compare exact static JavaScript export return shapes without execution; each side inline or {kind:"evidence-file",path,evidence_id?}',
    inputSchema: z.unknown(),
    sources: PAIRED_EVIDENCE_SOURCES,
    workflow: async (input, options) => {
      const { compareJavaScriptExportShapesEvidence } =
        await import("../application/javascript/JavaScriptApplicationWorkflowService.js");
      const result = await compareJavaScriptExportShapesEvidence(
        input,
        undefined,
        options,
      );
      return result.ok ? ok(result.value.evidence) : result;
    },
  });
};

interface JsonCommandOptions<Schema extends z.ZodType> {
  readonly cli: CliInstance;
  readonly logger: Logger;
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Schema;
  readonly workflow: (
    input: z.output<Schema>,
  ) => Promise<
    | { readonly ok: true; readonly value: JsonValue }
    | { readonly ok: false; readonly error: AnalysisError }
  >;
}

const registerJsonCommand = <Schema extends z.ZodType>({
  cli,
  logger,
  name,
  description,
  inputSchema,
  workflow,
}: JsonCommandOptions<Schema>): void => {
  cli.command(name, {
    description,
    args: z.object({
      inputJson: z.string().describe("Inline workflow JSON or JSON file path"),
    }),
    run: ({ args }) =>
      logCliCommand(logger, name, async () => {
        const input = await parseCliJsonInput(args.inputJson, name);
        if (!input.ok) return input.error;
        const parsed = inputSchema.safeParse(input.value);
        if (!parsed.success)
          return {
            error: "Application workflow failed",
            ...projectAnalysisError(
              analysisInputErrorFromIssues(
                name,
                parsed.error.issues,
                input.value,
              ),
            ),
          };
        const result = await workflow(parsed.data);
        return result.ok
          ? result.value
          : {
              error: "Application workflow failed",
              ...projectAnalysisError(result.error),
            };
      }),
  });
};
