import { projectCliAnalysisResult } from "./projectCliAnalysisResult.js";
import { localPathStringSchema } from "../domain/localPath.js";
import { compareWasmInterfaces } from "../application/wasm/WasmInterfaceComparisonService.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { z } from "incur";
import { wasmArtifactModule } from "../composition/wasm.js";
import { logCliCommand } from "../cliLogging.js";
import { ARTIFACT_COMPARISON_PROVIDER } from "../domain/comparisonEvidenceIdentity.js";
import { PAIRED_EVIDENCE_SOURCES } from "../domain/evidenceReference.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { registerEvidenceSourceCommand } from "./evidenceSourceCommand.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import {
  inspectWasmArtifactInputSchema,
  wasmArtifactPathsSchema,
} from "../domain/wasm/wasmArtifact.js";

/** Resolve all caller-selected artifact paths through the shared workflow. */
export const registerWasmCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  registerEvidenceSourceCommand(cli, logger, {
    name: CLI_COMMANDS.compareWasmInterfaces,
    operation: "compare_wasm_interfaces",
    inputOperation: "compare_wasm_interfaces",
    providerId: ARTIFACT_COMPARISON_PROVIDER.id,
    description:
      'Compare core WASM interfaces from two exact inspection Evidence records under a required scope; each side inline or {kind:"evidence-file",path,evidence_id?}',
    inputSchema: z.unknown(),
    sources: PAIRED_EVIDENCE_SOURCES,
    workflow: (input, options) => compareWasmInterfaces(input, options),
  });
  const service = wasmArtifactModule.create(environment);
  cli.command(wasmArtifactModule.cliCommand, {
    description: "Inspect an explicit local WASM artifact with WABT",
    args: z.object({
      path: localPathStringSchema.describe("Local WASM artifact"),
    }),
    options: z.object({
      commandTimeoutMs: inspectWasmArtifactInputSchema.shape.command_timeout_ms,
      glue_paths: wasmArtifactPathsSchema(localPathStringSchema)
        .optional()
        .describe("Selected local JavaScript glue paths"),
      candidate_paths: wasmArtifactPathsSchema(localPathStringSchema)
        .optional()
        .describe("Explicit local WASM candidates"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, wasmArtifactModule.cliCommand, () =>
          finishAnalysisCommand(
            () =>
              service.inspect(
                {
                  path: absoluteCallerPath(args.path),
                  ...(options.commandTimeoutMs === undefined
                    ? {}
                    : { command_timeout_ms: options.commandTimeoutMs }),
                  glue_paths: options.glue_paths?.map((path) =>
                    absoluteCallerPath(path),
                  ),
                  candidate_paths: options.candidate_paths?.map((path) =>
                    absoluteCallerPath(path),
                  ),
                },
                { signal },
              ),
            service,
            "wabt-artifact",
            "inspect_wasm_artifact",
            signal,
          ).then(projectCliAnalysisResult),
        ),
      ),
  });
};
