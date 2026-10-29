import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";

import { dotnetBundleFixture } from "../../src/artifacts/dotnet/DotnetBundle.fixture.js";
import { artifactInventoryResultSchema } from "../../src/domain/artifactGraph.js";
import type { Evidence } from "../../src/domain/evidence.js";
import { connectArtifactComparisonMcp } from "../fixtures/artifactComparisonMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";

it("compares a .NET bundle member's declared file type, not the header version", async () => {
  const root = await createTestTempDirectory("rea-dotnet-comparison-");
  const { inspect: inspectFile, compare } =
    await connectArtifactComparisonMcp();
  const bytes = Buffer.from("owned assembly bytes");
  const inspect = async (
    name: string,
    fileType: number,
    majorVersion?: number,
  ): Promise<Evidence> => {
    const path = join(root, name);
    await writeFile(
      path,
      dotnetBundleFixture([{ path: "App.dll", bytes, fileType }], majorVersion)
        .bytes,
    );
    return inspectFile(path);
  };
  const memberChanges = async (left: Evidence, right: Evidence) =>
    (await compare(left, right)).changes.filter(
      ({ logical_path }) => logical_path !== ".",
    );
  const member = (evidence: Evidence) => {
    const occurrence = artifactInventoryResultSchema
      .parse(evidence.normalized_result)
      .occurrences.find(({ logical_path }) => logical_path === "App.dll");
    if (occurrence === undefined) throw new Error("Missing App.dll");
    return occurrence;
  };

  const assembly = await inspect("assembly", 1);
  // File type 2 declares a native binary, so the host treats the same bytes
  // another way.
  const native = await inspect("native", 2);
  expect(member(native)).toMatchObject({
    artifact_id: member(assembly).artifact_id,
    format_metadata: { kind: "dotnet-bundle-entry", file_type: 2 },
  });
  expect(await memberChanges(assembly, native)).toMatchObject([
    {
      logical_path: "App.dll",
      classification: "changed",
      dimensions: ["metadata"],
    },
  ]);

  // Every member repeats the header version, which the host's bytes hold.
  const older = await inspect("older", 1, 2);
  expect(member(older)).toMatchObject({
    artifact_id: member(assembly).artifact_id,
    format_metadata: { major_version: 2, file_type: 1 },
  });
  expect(await memberChanges(assembly, older)).toEqual([]);
});
