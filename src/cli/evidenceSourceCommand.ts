import { z } from "incur";
import type { Logger } from "pino";

import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { parseCliJsonInput, resolveCliJsonPaths } from "../cliJsonInput.js";
import { logCliCommand } from "../cliLogging.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Evidence } from "../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import type { Result } from "../domain/result.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import type { CliInstance } from "./types.js";

/** One CLI workflow whose request names Evidence sources. */
export interface EvidenceSourceCommand<Schema extends z.ZodType> {
  readonly name: string;
  readonly operation: string;
  /** The operation a JSON input failure names; the command name when omitted. */
  readonly inputOperation?: string;
  readonly providerId: string;
  readonly description: string;
  /** The request schema checked here; z.unknown() leaves the request to the workflow. */
  readonly inputSchema: Schema;
  /** Request fields that name Evidence; a relative Evidence-file path resolves from the working directory. */
  readonly sources: readonly string[];
  readonly workflow: (
    input: z.output<Schema>,
    options: {
      readonly signal: AbortSignal;
      readonly resources: ArtifactResourceScope;
    },
  ) => Promise<Result<Evidence, AnalysisError>>;
}

/** Register a one-shot workflow that owns the resources its Evidence-file reads use. */
export const registerEvidenceSourceCommand = <Schema extends z.ZodType>(
  cli: CliInstance,
  logger: Logger,
  command: EvidenceSourceCommand<Schema>,
): void => {
  const { name, operation, inputSchema, sources, workflow } = command;
  cli.command(name, {
    description: command.description,
    args: z.object({
      inputJson: z.string().describe("Inline workflow JSON or JSON file path"),
    }),
    run: ({ args }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, name, async () => {
          const input = await parseCliJsonInput(
            args.inputJson,
            command.inputOperation ?? name,
            signal,
          );
          if (!input.ok) return input.error;
          const value = resolveCliJsonPaths(
            input.value,
            sources.map((field) => [field, "path"]),
          );
          const parsed = inputSchema.safeParse(value);
          if (!parsed.success)
            return {
              error: "Application workflow failed",
              ...projectAnalysisError(
                analysisInputErrorFromIssues(
                  operation,
                  parsed.error.issues,
                  value,
                ),
              ),
            };
          const resources = new ArtifactResourceScope();
          const result = await finishAnalysisCommand(
            () => workflow(parsed.data, { signal, resources }),
            resources,
            command.providerId,
            operation,
            signal,
          );
          return result.ok
            ? result.value
            : { error: "Application workflow failed", ...result.error };
        }),
      ),
  });
};
