import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";

import { cArchiveExecutable } from "../../src/artifacts/pyinstaller/CArchive.fixture.js";
import { artifactComparisonResultSchema } from "../../src/domain/artifactComparison.js";
import { artifactInspectionResultSchema } from "../../src/domain/artifactInspection.js";
import { artifactInventoryResultSchema } from "../../src/domain/artifactGraph.js";
import { parseEvidence, type Evidence } from "../../src/domain/evidence.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";

it("reports a changed PyInstaller declaration whose member bytes are unavailable", async () => {
  const root = await createTestTempDirectory("rea-pyinstaller-comparison-");
  const { call } = await connectLocalToolsMcp();
  const inspect = async (name: string, member: string): Promise<Evidence> => {
    const path = join(root, name);
    await writeFile(
      path,
      cArchiveExecutable({
        layout: "2.1",
        pythonVersion: 309,
        members: [
          {
            name: member,
            typeCode: "n",
            payload: Buffer.from("target"),
            compress: false,
          },
        ],
      }),
    );
    const opened = await call("open_binary", { path });
    expect(opened.isError, JSON.stringify(opened)).not.toBe(true);
    const response = await call("inspect_artifact", {});
    expect(response.isError, JSON.stringify(response)).not.toBe(true);
    const inventory = artifactInspectionResultSchema
      .parse(parseEvidence(response.structuredContent).normalized_result)
      .substeps.find(
        ({ operation }) => operation === "inventory_artifact",
      )?.evidence;
    if (inventory === undefined) throw new Error("Missing inventory Evidence");
    return parseEvidence(inventory);
  };
  const link = (evidence: Evidence, path: string) => {
    const occurrence = artifactInventoryResultSchema
      .parse(evidence.normalized_result)
      .occurrences.find(({ logical_path }) => logical_path === path);
    if (occurrence === undefined) throw new Error(`Missing ${path}`);
    return occurrence;
  };

  // A rebuild on another filesystem can store the link name decomposed.
  // Normalization pairs the links; their stored names stay distinct.
  const nfc = "café-link";
  const left = await inspect("nfc", nfc);
  const right = await inspect("nfd", "café-link");
  expect(link(left, nfc)).toMatchObject({
    hash_status: "not-hashed",
    format_metadata: { source_name: nfc },
  });
  expect(link(right, nfc)).toMatchObject({
    hash_status: "not-hashed",
    format_metadata: { source_name: "café-link" },
  });

  const response = await call("compare_artifacts", { left, right });
  expect(response.isError, JSON.stringify(response)).not.toBe(true);
  const result = artifactComparisonResultSchema.parse(
    parseEvidence(response.structuredContent).normalized_result,
  );
  expect(
    result.changes.find(({ logical_path }) => logical_path === nfc),
  ).toMatchObject({
    classification: "changed",
    dimensions: ["metadata", "availability"],
    left_occurrence_id: link(left, nfc).occurrence_id,
    right_occurrence_id: link(right, nfc).occurrence_id,
  });
});
