import type { Logger } from "pino";

import {
  compareArtifactEvidence,
  resolveArtifactComparisonSources,
} from "../application/artifacts/ArtifactComparisonEvidence.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { artifactComparisonInputSchema } from "../contracts/sessionToolSchemas.js";
import { ARTIFACT_COMPARISON_PROVIDER } from "../domain/comparisonEvidenceIdentity.js";
import { PAIRED_EVIDENCE_SOURCES } from "../domain/evidenceReference.js";
import { ok } from "../domain/result.js";
import { registerEvidenceSourceCommand } from "./evidenceSourceCommand.js";
import type { CliInstance } from "./types.js";

const OPERATION = "compare_artifacts";

/** Compare artifact inventories through the same source owners and workflow as MCP. */
export const registerArtifactComparisonCommand = (
  cli: CliInstance,
  logger: Logger,
): void =>
  registerEvidenceSourceCommand(cli, logger, {
    name: CLI_COMMANDS.compareArtifacts,
    operation: OPERATION,
    inputOperation: OPERATION,
    providerId: ARTIFACT_COMPARISON_PROVIDER.id,
    description:
      'Compare two artifact inventories named as {left, right}: complete Evidence or {kind:"evidence-file",path,evidence_id?}. A one-shot command retains no session Evidence for retained-evidence references.',
    inputSchema: artifactComparisonInputSchema,
    sources: PAIRED_EVIDENCE_SOURCES,
    workflow: async (input, options) => {
      const sources = await resolveArtifactComparisonSources(
        input,
        undefined,
        options,
      );
      if (!sources.ok) return sources;
      const compared = compareArtifactEvidence(sources.value);
      return compared.ok ? ok(compared.value.evidence) : compared;
    },
  });
