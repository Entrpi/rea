import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { compareSourceToBundleCliInputSchema } from "../contracts/javascript/applicationWorkflowInputContracts.js";
import { APPLICATION_EVIDENCE_SOURCE } from "../domain/evidenceReference.js";
import { JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER } from "../domain/investigationProviders.js";
import { ok } from "../domain/result.js";
import { registerEvidenceSourceCommand } from "./evidenceSourceCommand.js";

/** CLI file transport delegates graph authentication and comparison to the same owners as MCP. */
export const registerSourceToBundleCommand = (
  cli: CliInstance,
  logger: Logger,
): void =>
  registerEvidenceSourceCommand(cli, logger, {
    name: CLI_COMMANDS.compareSourceToBundle,
    operation: "compare_source_to_bundle",
    providerId: JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER.id,
    description:
      'Compare historical source (inline graph or reference {kind:file,path}) with authenticated application Evidence, inline or {kind:"evidence-file",path,evidence_id?}. Save the complete JSON to query with inspect-analysis-view.',
    inputSchema: compareSourceToBundleCliInputSchema,
    // Only the Evidence-file path is transport; the reference keeps its requested path.
    sources: APPLICATION_EVIDENCE_SOURCE,
    workflow: async (input, options) => {
      const { resolveSourceToBundleSources } =
        await import("../application/javascript/SourceToBundleReference.js");
      const sources = await resolveSourceToBundleSources(
        input,
        undefined,
        options,
      );
      if (!sources.ok) return sources;
      const { compareSourceToBundleEvidence } =
        await import("../application/javascript/JavaScriptApplicationWorkflowService.js");
      const compared = compareSourceToBundleEvidence(sources.value);
      return compared.ok ? ok(compared.value.evidence) : compared;
    },
  });
