import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";

import { artifactComparisonResultSchema } from "../../src/domain/artifactComparison.js";
import { artifactInspectionResultSchema } from "../../src/domain/artifactInspection.js";
import { artifactInventoryResultSchema } from "../../src/domain/artifactGraph.js";
import { parseEvidence, type Evidence } from "../../src/domain/evidence.js";
import { buildGodotPck } from "../fixtures/godotPck.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";

it("pairs a Godot PCK member across stored res:// spellings", async () => {
  const root = await createTestTempDirectory("rea-pck-comparison-");
  const { call } = await connectLocalToolsMcp();
  const inspect = async (name: string, path: string): Promise<Evidence> => {
    const file = join(root, name);
    await writeFile(file, buildGodotPck(2, [{ path, data: "extends Node\n" }]));
    const opened = await call("open_binary", { path: file });
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
  const member = (evidence: Evidence) => {
    const occurrence = artifactInventoryResultSchema
      .parse(evidence.normalized_result)
      .occurrences.find(
        ({ logical_path }) => logical_path === "scenes/main.gd",
      );
    if (occurrence === undefined) throw new Error("Missing scenes/main.gd");
    return occurrence;
  };

  // Godot 4.3 exports store res:// paths and 4.4.1 exports do not. Godot
  // looks both up by the same simplified path, which logical_path holds.
  const prefixed = await inspect("prefixed.pck", "res://scenes/main.gd");
  const relative = await inspect("relative.pck", "scenes/main.gd");
  expect(member(prefixed).format_metadata).toMatchObject({
    source_path: "res://scenes/main.gd",
  });
  expect(member(relative).format_metadata).toMatchObject({
    source_path: "scenes/main.gd",
  });
  expect(member(relative).artifact_id).toBe(member(prefixed).artifact_id);

  const response = await call("compare_artifacts", {
    left: prefixed,
    right: relative,
  });
  expect(response.isError, JSON.stringify(response)).not.toBe(true);
  const result = artifactComparisonResultSchema.parse(
    parseEvidence(response.structuredContent).normalized_result,
  );
  expect(
    result.changes.filter(({ logical_path }) => logical_path !== "."),
  ).toEqual([]);
  expect(result.summary).toMatchObject({ unchanged: 1, unknown: 0 });
});
