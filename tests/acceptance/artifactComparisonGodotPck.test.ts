import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";

import { artifactComparisonResultSchema } from "../../src/domain/artifactComparison.js";
import { artifactInspectionResultSchema } from "../../src/domain/artifactInspection.js";
import { artifactInventoryResultSchema } from "../../src/domain/artifactGraph.js";
import { parseEvidence, type Evidence } from "../../src/domain/evidence.js";
import { buildGodotPck, type GodotPckMember } from "../fixtures/godotPck.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";

/** Inspect one-member packs and compare their inventories through MCP. */
const connectPackComparison = async () => {
  const root = await createTestTempDirectory("rea-pck-comparison-");
  const { call } = await connectLocalToolsMcp();
  const inspect = async (
    name: string,
    packMember: GodotPckMember,
  ): Promise<Evidence> => {
    const file = join(root, name);
    await writeFile(file, buildGodotPck(2, [packMember]));
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
  const compare = async (left: Evidence, right: Evidence) => {
    const response = await call("compare_artifacts", { left, right });
    expect(response.isError, JSON.stringify(response)).not.toBe(true);
    return artifactComparisonResultSchema.parse(
      parseEvidence(response.structuredContent).normalized_result,
    );
  };
  return { inspect, compare };
};

const member = (evidence: Evidence) => {
  const occurrence = artifactInventoryResultSchema
    .parse(evidence.normalized_result)
    .occurrences.find(({ logical_path }) => logical_path === "scenes/main.gd");
  if (occurrence === undefined) throw new Error("Missing scenes/main.gd");
  return occurrence;
};

it("pairs a Godot PCK member across stored res:// spellings", async () => {
  const { inspect, compare } = await connectPackComparison();

  // Godot 4.3 exports store res:// paths and 4.4.1 exports do not. Godot
  // looks both up by the same simplified path, which logical_path holds.
  const prefixed = await inspect("prefixed.pck", {
    path: "res://scenes/main.gd",
    data: "extends Node\n",
  });
  const relative = await inspect("relative.pck", {
    path: "scenes/main.gd",
    data: "extends Node\n",
  });
  expect(member(prefixed).format_metadata).toMatchObject({
    source_path: "res://scenes/main.gd",
  });
  expect(member(relative).format_metadata).toMatchObject({
    source_path: "scenes/main.gd",
  });
  expect(member(relative).artifact_id).toBe(member(prefixed).artifact_id);

  const result = await compare(prefixed, relative);
  expect(
    result.changes.filter(({ logical_path }) => logical_path !== "."),
  ).toEqual([]);
  expect(result.summary).toMatchObject({ unchanged: 1, unknown: 0 });
});

it("reports a Godot PCK member that becomes encrypted", async () => {
  const { inspect, compare } = await connectPackComparison();
  const script = { path: "res://scenes/main.gd", data: "extends Node\n" };
  const plain = await inspect("plain.pck", script);
  const encrypted = await inspect("encrypted.pck", { ...script, flags: 1 });
  // REA does not decrypt members, so the encrypted member has no content.
  expect(member(encrypted)).toMatchObject({
    artifact_id: null,
    encrypted: true,
    hash_status: "unavailable",
  });

  // The encryption change is known; whether the script changed is not.
  const result = await compare(plain, encrypted);
  expect(
    result.changes.filter(({ logical_path }) => logical_path !== "."),
  ).toMatchObject([
    {
      logical_path: "scenes/main.gd",
      classification: "unknown",
      dimensions: ["metadata", "availability"],
      left_occurrence_id: member(plain).occurrence_id,
      right_occurrence_id: member(encrypted).occurrence_id,
    },
  ]);
});
