import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { TextReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";
import { expect, it } from "vitest";

import {
  artifactComparisonResultSchema,
  type ArtifactComparisonResult,
} from "../../src/domain/artifactComparison.js";
import { artifactInspectionResultSchema } from "../../src/domain/artifactInspection.js";
import { artifactInventoryResultSchema } from "../../src/domain/artifactGraph.js";
import { parseEvidence, type Evidence } from "../../src/domain/evidence.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";

/** A ZIP member with the Unix mode its external attributes declare. */
interface ZipMember {
  readonly name: string;
  readonly data: string;
  readonly mode: number;
  readonly password?: string;
}

/** Inspect ZIP archives and compare their inventories through MCP. */
const connectZipComparison = async () => {
  const root = await createTestTempDirectory("rea-zip-comparison-");
  const { call } = await connectLocalToolsMcp();
  const inspect = async (
    name: string,
    members: readonly ZipMember[],
  ): Promise<Evidence> => {
    const writer = new ZipWriter(new Uint8ArrayWriter(), {
      versionMadeBy: 3 << 8,
    });
    for (const { name: path, data, mode, password } of members)
      await writer.add(path, new TextReader(data), {
        externalFileAttributes: (mode << 16) >>> 0,
        ...(password === undefined ? {} : { password }),
      });
    const file = join(root, name);
    await writeFile(file, await writer.close());
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

const member = (evidence: Evidence, path: string) => {
  const occurrence = artifactInventoryResultSchema
    .parse(evidence.normalized_result)
    .occurrences.find(({ logical_path }) => logical_path === path);
  if (occurrence === undefined) throw new Error(`Missing ${path}`);
  return occurrence;
};

/** The archive root differs whenever members do; compare members only. */
const memberChanges = (result: ArtifactComparisonResult) =>
  result.changes.filter(({ logical_path }) => logical_path !== ".");

it("reports a ZIP member that becomes a symlink", async () => {
  const { inspect, compare } = await connectZipComparison();
  // A symlink member stores its target as data, so both members hold the
  // same bytes; only the declared entry kind differs.
  const file = await inspect("file.zip", [
    { name: "current", data: "target.txt", mode: 0o100644 },
  ]);
  const link = await inspect("link.zip", [
    { name: "current", data: "target.txt", mode: 0o120777 },
  ]);
  expect(member(file, "current")).toMatchObject({
    entry_kind: "file",
    hash_status: "verified",
    executable: false,
  });
  // REA does not read symlink targets, so the link has no content.
  expect(member(link, "current")).toMatchObject({
    entry_kind: "symlink",
    artifact_id: null,
    hash_status: "not-hashed",
    executable: false,
  });

  expect(memberChanges(await compare(file, link))).toMatchObject([
    {
      logical_path: "current",
      classification: "changed",
      dimensions: ["metadata", "availability"],
      left_occurrence_id: member(file, "current").occurrence_id,
      right_occurrence_id: member(link, "current").occurrence_id,
    },
  ]);
  // Without a declared change, unread content stays unknown.
  expect(memberChanges(await compare(link, link))).toMatchObject([
    {
      logical_path: "current",
      classification: "unknown",
      dimensions: ["availability"],
    },
  ]);
});

it("reports an executable mode change on an encrypted ZIP member", async () => {
  const { inspect, compare } = await connectZipComparison();
  const tool = { name: "tool", data: "#!/bin/sh\n", password: "fixture" };
  const plain = await inspect("plain.zip", [{ ...tool, mode: 0o100644 }]);
  const marked = await inspect("marked.zip", [{ ...tool, mode: 0o100755 }]);
  // REA does not decrypt members, so neither side has content.
  for (const [evidence, executable] of [
    [plain, false],
    [marked, true],
  ] as const)
    expect(member(evidence, "tool")).toMatchObject({
      artifact_id: null,
      encrypted: true,
      hash_status: "unavailable",
      executable,
    });

  expect(memberChanges(await compare(plain, marked))).toMatchObject([
    {
      logical_path: "tool",
      classification: "changed",
      dimensions: ["executable", "availability"],
    },
  ]);
  // With equal declarations, the encrypted bytes stay unknown.
  expect(memberChanges(await compare(plain, plain))).toMatchObject([
    {
      logical_path: "tool",
      classification: "unknown",
      dimensions: ["availability"],
    },
  ]);
});
