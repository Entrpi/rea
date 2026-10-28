import type {
  EvidenceWriter,
  EvidenceUnknownWriter,
} from "../../application/investigation/InvestigationRecordPort.js";
import type { BinarySessionPort } from "../../application/binary/BinarySessionPort.js";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "../analysisAdmission.js";

/** Shared services for registering managed-code workflow tools. */
export interface ManagedWorkflowToolRegistration {
  readonly withAdmittedAnalysis?: WithAdmittedAnalysis;
  /** Retains descriptors from Evidence-file sources whose close failed. */
  readonly artifactResources: ArtifactResourceScope;
  readonly logger: Logger;
  readonly recordEvidence: EvidenceWriter["recordEvidence"] | undefined;
  readonly recordEvidenceWithUnknown:
    | EvidenceUnknownWriter["recordEvidenceWithUnknown"]
    | undefined;
  readonly session: BinarySessionPort;
}
