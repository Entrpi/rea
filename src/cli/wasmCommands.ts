import { projectCliAnalysisResult } from "./projectCliAnalysisResult.js";
import { localPathStringSchema } from "../domain/localPath.js";
import { compareWasmInterfaces } from "../application/wasm/WasmInterfaceComparisonService.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { parseCliJsonInput, resolveCliJsonPaths } from "../cliJsonInput.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { z } from "incur";
import { wasmArtifactModule } from "../composition/wasm.js";
import { logCliCommand } from "../cliLogging.js";
import { ARTIFACT_COMPARISON_PROVIDER } from "../domain/comparisonEvidenceIdentity.js";
import { ok } from "../domain/result.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
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
  cli.command(CLI_COMMANDS.compareWasmInterfaces, {
    description:
      "Compare core WASM interfaces from two exact inspection Evidence records",
    args: z.object({
      input: z
        .string()
        .describe(
          'Inline JSON or input file containing required scope and left/right complete Evidence or {kind:"evidence-file",path,evidence_id?}',
        ),
    }),
    run: ({ args }) =>
      withCommandCancellation(async (signal) =>
        logCliCommand(logger, CLI_COMMANDS.compareWasmInterfaces, async () => {
          const input = await parseCliJsonInput(
            args.input,
            "compare_wasm_interfaces",
            signal,
          );
          if (!input.ok) return input.error;
          // Evidence-file paths are resolved against the operator's working directory.
          const value = resolveCliJsonPaths(input.value, [
            ["left", "path"],
            ["right", "path"],
          ]);
          const resources = new ArtifactResourceScope();
          return projectCliAnalysisResult(
            await finishAnalysisCommand(
              async () => {
                const result = await compareWasmInterfaces(value, {
                  signal,
                  resources,
                });
                return result.ok ? ok(result.value.evidence) : result;
              },
              resources,
              ARTIFACT_COMPARISON_PROVIDER.id,
              "compare_wasm_interfaces",
              signal,
            ),
          );
        }),
      ),
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
