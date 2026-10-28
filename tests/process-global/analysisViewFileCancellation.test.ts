import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import {
  analysisViewCaptureEvidence,
  environmentManifestCaptureFixture,
} from "../fixtures/analysisView.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { readEvidenceFileSource } from "../../src/application/EvidenceFileSource.js";
import { inspectAnalysisView } from "../../src/application/analysisView/AnalysisViewService.js";

// This module mock needs an isolated graph even if another service imports the workflow first.
vi.mock("../../src/application/EvidenceFileSource.js", {
  spy: true,
});

it("prefers cancellation observed after failed Evidence-file authentication", async () => {
  const controller = new AbortController();
  const parent = analysisViewCaptureEvidence(
    environmentManifestCaptureFixture(),
  );
  const root = await createTestTempDirectory("rea-analysis-view-cancel-");
  const path = join(root, "parent.json");
  await writeFile(
    path,
    JSON.stringify({ ...parent, evidence_id: `ev_${"0".repeat(64)}` }),
  );
  const { readEvidenceFileSource: read } = await vi.importActual<
    typeof import("../../src/application/EvidenceFileSource.js")
  >("../../src/application/EvidenceFileSource.js");
  // Abort at the completed read boundary, before its authentication failure is delivered.
  vi.mocked(readEvidenceFileSource).mockImplementationOnce(async (...args) => {
    const loaded = await read(...args);
    controller.abort();
    return loaded;
  });
  expect(
    await inspectAnalysisView(
      {
        source: { kind: "evidence-file", path },
        view: { kind: "environment-manifest" },
      },
      undefined,
      { signal: controller.signal },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  expect(readEvidenceFileSource).toHaveBeenCalledTimes(1);
  expect(controller.signal.aborted).toBe(true);
});
