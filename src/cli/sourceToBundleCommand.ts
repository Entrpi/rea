import { z } from "incur";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { parseCliJsonInput, resolveCliJsonPaths } from "../cliJsonInput.js";
import { logCliCommand } from "../cliLogging.js";
import { compareSourceToBundleCliInputSchema } from "../contracts/javascript/applicationWorkflowInputContracts.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";

/** CLI file transport delegates graph authentication and comparison to the same owners as MCP. */
export const registerSourceToBundleCommand = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const name = CLI_COMMANDS.compareSourceToBundle;
  cli.command(name, {
    description:
      'Compare historical source (inline graph or reference {kind:file,path}) with authenticated application Evidence, inline or {kind:"evidence-file",path,evidence_id?}. Save the complete JSON to query with inspect-analysis-view.',
    args: z.object({
      inputJson: z.string().describe("Inline workflow JSON or JSON file path"),
    }),
    run: ({ args }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, name, async () => {
          const input = await parseCliJsonInput(args.inputJson, name, signal);
          if (!input.ok) return input.error;
          // Only the Evidence-file path is transport; the reference keeps its requested path.
          const value = resolveCliJsonPaths(input.value, [
            ["application", "path"],
          ]);
          const parsed = compareSourceToBundleCliInputSchema.safeParse(value);
          if (!parsed.success)
            return {
              error: "Application workflow failed",
              ...projectAnalysisError(
                analysisInputErrorFromIssues(name, parsed.error.issues, value),
              ),
            };
          const resources = new ArtifactResourceScope();
          const result = await finishAnalysisCommand(
            async () => {
              const { resolveSourceToBundleSources } =
                await import("../application/javascript/SourceToBundleReference.js");
              const sources = await resolveSourceToBundleSources(
                parsed.data,
                undefined,
                { signal, resources },
              );
              if (!sources.ok) return sources;
              const { compareSourceToBundleEvidence } =
                await import("../application/javascript/JavaScriptApplicationWorkflowService.js");
              const compared = compareSourceToBundleEvidence(sources.value);
              return compared.ok
                ? { ok: true, value: compared.value.evidence }
                : compared;
            },
            resources,
            "javascript-application-workflow",
            "compare_source_to_bundle",
            signal,
          );
          return result.ok
            ? result.value
            : { error: "Application workflow failed", ...result.error };
        }),
      ),
  });
};
