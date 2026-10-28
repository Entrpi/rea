import { compareWasmInterfaces } from "../application/wasm/WasmInterfaceComparisonService.js";
import { COMPARE_WASM_INTERFACES_CONTRACT } from "../contracts/wasm/wasmComparisonContracts.js";
import { recordEvidenceSources } from "../application/investigation/recordEvidenceSources.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";

import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { WasmArtifactService } from "../application/wasm/WasmArtifactService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { EvidenceLookup } from "../application/EvidenceInputResolver.js";
import { ok } from "../domain/result.js";
import { wasmArtifactModule } from "../composition/wasm.js";
import type { Logger } from "pino";
import {
  createEvidenceToolHandler,
  createRetainedSummaryToolHandler,
} from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import {
  applicationToolRegistrationOptions,
  toolRegistrationOptions,
} from "./toolRegistrationOptions.js";

/** Bind the named WASM contract to shared validation and session Evidence recording. */
export const registerWasmTools = (
  server: EvidenceMcpServer,
  service: Pick<WasmArtifactService, "inspect">,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
  evidenceById?: EvidenceLookup,
  artifactResources?: ArtifactResourceScope,
): void => {
  const comparison = COMPARE_WASM_INTERFACES_CONTRACT;
  const compareHandler = createEvidenceToolHandler(
    server,
    async (rawInput, options) => {
      const result = await compareWasmInterfaces(
        rawInput,
        artifactResources === undefined
          ? options
          : { ...options, resources: artifactResources },
        evidenceById,
      );
      if (!result.ok) return result;
      const recorded = recordEvidenceSources(
        recordEvidence,
        result.value.sources,
      );
      return recorded.ok ? ok(result.value.evidence) : recorded;
    },
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    comparison.name,
    toolRegistrationOptions(comparison),
    compareHandler(comparison),
  );
  const contract = wasmArtifactModule.contract;
  const handler = createRetainedSummaryToolHandler(
    server,
    contract,
    (input, options) => service.inspect(input, options),
    logger,
    { recordEvidence, evidenceById },
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    applicationToolRegistrationOptions(contract),
    handler,
  );
};
