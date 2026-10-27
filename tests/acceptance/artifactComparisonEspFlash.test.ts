import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";

import {
  ESP32C3_BOOTLOADER_SEGMENTS,
  espImage,
} from "../../src/domain/firmware/espImage.fixture.js";
import {
  TWO_OTA_PARTITIONS,
  espFlashDump,
  partitionTable,
} from "../../src/domain/firmware/espFlash.fixture.js";
import { artifactComparisonResultSchema } from "../../src/domain/artifactComparison.js";
import { artifactInspectionResultSchema } from "../../src/domain/artifactInspection.js";
import { artifactInventoryResultSchema } from "../../src/domain/artifactGraph.js";
import { parseEvidence, type Evidence } from "../../src/domain/evidence.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";

const BOOTLOADER = {
  at: 0,
  bytes: espImage({ segments: ESP32C3_BOOTLOADER_SEGMENTS }),
};

/** A table without an MD5 whose first entry has these label bytes. */
const labelBytes = (bytes: readonly number[]): Buffer => {
  const table = Buffer.from(
    partitionTable(TWO_OTA_PARTITIONS, { md5: "absent" }),
  );
  table.fill(0, 12, 28);
  Buffer.from(bytes).copy(table, 12);
  return table;
};

it("reports an ESP partition whose declaration alone changed", async () => {
  const root = await createTestTempDirectory("rea-esp-flash-comparison-");
  const { call } = await connectLocalToolsMcp();
  const inspect = async (name: string, table: Buffer): Promise<Evidence> => {
    const path = join(root, name);
    await writeFile(path, espFlashDump({ bootloader: BOOTLOADER, table }));
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
  const compare = async (left: Evidence, right: Evidence) => {
    const response = await call("compare_artifacts", { left, right });
    expect(response.isError, JSON.stringify(response)).not.toBe(true);
    return artifactComparisonResultSchema.parse(
      parseEvidence(response.structuredContent).normalized_result,
    );
  };
  const occurrence = (evidence: Evidence, path: string) => {
    const found = artifactInventoryResultSchema
      .parse(evidence.normalized_result)
      .occurrences.find(({ logical_path }) => logical_path === path);
    if (found === undefined) throw new Error(`Missing ${path}`);
    return found;
  };
  const changedPaths = (result: { changes: { logical_path: string }[] }) =>
    result.changes
      .map(({ logical_path }) => logical_path)
      .filter((path) => path !== ".")
      .sort();

  // The same partition bytes, with nvs declared read-only.
  const readonly = TWO_OTA_PARTITIONS.map((part) =>
    part.label === "nvs" ? { ...part, flags: 0x2 } : part,
  );
  const left = await inspect("flash.bin", partitionTable(TWO_OTA_PARTITIONS));
  const right = await inspect("readonly.bin", partitionTable(readonly));
  const leftNvs = occurrence(left, "partitions/nvs.bin");
  const rightNvs = occurrence(right, "partitions/nvs.bin");
  expect(rightNvs.artifact_id).toBe(leftNvs.artifact_id);
  expect(leftNvs.format_metadata).toMatchObject({ readonly: false });
  expect(rightNvs.format_metadata).toMatchObject({ readonly: true });
  const changed = await compare(left, right);
  expect(
    changed.changes.find(
      ({ logical_path }) => logical_path === "partitions/nvs.bin",
    ),
  ).toEqual({
    classification: "changed",
    logical_path: "partitions/nvs.bin",
    dimensions: ["metadata"],
    left_occurrence_id: leftNvs.occurrence_id,
    right_occurrence_id: rightNvs.occurrence_id,
    left_artifact_id: leftNvs.artifact_id,
    right_artifact_id: rightNvs.artifact_id,
    evidence_links: [left.evidence_id, right.evidence_id],
  });
  // Only the table's bytes and the declaration it gives nvs changed.
  expect(changedPaths(changed)).toEqual([
    "partition-table.bin",
    "partitions/nvs.bin",
  ]);

  // Labels that are not UTF-8 compare by their bytes.
  const first = await inspect("label-a.bin", labelBytes([0xff, 0x01]));
  const second = await inspect("label-b.bin", labelBytes([0xfe, 0x01]));
  expect(occurrence(first, "partitions/0.bin").format_metadata).toMatchObject({
    label: null,
    label_hex: "ff01",
  });
  expect(changedPaths(await compare(first, second))).toEqual([
    "partition-table.bin",
    "partitions/0.bin",
  ]);

  // Equal declarations leave every partition unchanged.
  const same = await compare(
    left,
    await inspect("copy.bin", partitionTable(TWO_OTA_PARTITIONS)),
  );
  expect(same.changes).toEqual([]);
});
