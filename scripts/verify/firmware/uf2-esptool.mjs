#!/usr/bin/env node
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createVerifierCommands } from "../../lib/verify-commands.mjs";
import { withVerifierCleanup } from "../../lib/verifier-cleanup.mjs";

// Optional verification tool only; the UF2 reader starts no tool.
const python = process.env.REA_ESPTOOL_PYTHON ?? "python3";
const entrypoint = fileURLToPath(new URL("../../rea.mjs", import.meta.url));
const options = { maxBuffer: 16 * 1024 * 1024, timeout: 120_000 };
/** Every tool runs as an owned process tree that close() stops. */
const commands = await createVerifierCommands();

let workspace;
const path = (name) => join(workspace, name);

/** Deterministic input bytes; lengths include one that is not word-aligned. */
const input = (length, seed) =>
  Buffer.from(Array.from({ length }, (_, index) => (index * 13 + seed) & 0xff));

const tool = async (args) => {
  const { stdout, stderr } = await commands.exec(
    python,
    ["-m", "esptool", ...args],
    options,
  );
  return `${stdout}${stderr}`;
};

/** esptool's own family ID for a chip: the oracle REA's table must match. */
const familyOf = async (chip) => {
  const { stdout } = await commands.exec(
    python,
    [
      "-c",
      "import sys, esptool.targets as t; print(t.CHIP_DEFS[sys.argv[1]].UF2_FAMILY_ID)",
      chip,
    ],
    options,
  );
  return Number(stdout.trim());
};

const rea = async (command, file) => {
  const { stdout } = await commands.exec(
    process.execPath,
    [entrypoint, command, file, "--json"],
    {
      ...options,
      env: {
        ...process.env,
        REA_LOG_LEVEL: "silent",
        TMPDIR: workspace,
        TMP: workspace,
        TEMP: workspace,
      },
    },
  );
  return JSON.parse(stdout).normalized_result;
};

const familyDirectory = (familyId) =>
  `family-0x${familyId.toString(16).padStart(8, "0")}`;
const hex32 = (value) => `0x${value.toString(16).padStart(8, "0")}`;

await withVerifierCleanup(async () => {
  const versionText = await tool(["version"]);
  const version = /\bv?(\d+)\.(\d+)\.(\d+)\b/u.exec(versionText);
  assert.ok(version, `Unrecognized esptool version: ${versionText}`);
  const v5 = Number(version[1]) >= 5;
  workspace = await mkdtemp(join(tmpdir(), "rea-uf2-esptool-"));
  const files = {
    bootloader: input(1000, 1),
    table: input(3072, 2),
    app: input(501, 3),
  };
  for (const [name, bytes] of Object.entries(files))
    await writeFile(path(`${name}.bin`), bytes);
  const merge = (chip, output, layout, extra = []) =>
    tool([
      "--chip",
      chip,
      v5 ? "merge-bin" : "merge_bin",
      "--format",
      "uf2",
      ...extra,
      "-o",
      path(output),
      ...layout.flatMap(([address, name]) => [
        hex32(address),
        path(`${name}.bin`),
      ]),
    ]);
  const cases = [
    {
      name: "esp32s3.uf2",
      chip: "esp32s3",
      layout: [
        [0x0, "bootloader"],
        [0x8000, "table"],
        [0x10000, "app"],
      ],
      extra: [],
      md5: true,
      payload: 452,
    },
    {
      name: "esp32s2-tinyuf2.uf2",
      chip: "esp32s2",
      layout: [
        [0x1000, "bootloader"],
        [0x8000, "table"],
      ],
      extra: ["--chunk-size", "256", "--md5-disable"],
      md5: false,
      payload: 256,
    },
  ];
  const report = { esptool: version[0], cases: [] };
  for (const entry of cases) {
    await merge(entry.chip, entry.name, entry.layout, entry.extra);
    entry.familyId = await familyOf(entry.chip);
  }
  // The UF2 specification makes a multi-family file by concatenation.
  await writeFile(
    path("concatenated.uf2"),
    Buffer.concat([
      await readFile(path(cases[0].name)),
      await readFile(path(cases[1].name)),
    ]),
  );
  for (const file of [
    ...cases.map((entry) => entry.name),
    "concatenated.uf2",
  ]) {
    const included =
      file === "concatenated.uf2"
        ? cases
        : cases.filter((entry) => entry.name === file);
    const inspected = await rea("inspect-artifact", path(file));
    const inventory = inspected.substeps[0].evidence.normalized_result;
    assert.equal(inventory.manifest.root_format, "uf2", file);
    assert.equal(inventory.coverage.status, "complete", file);
    const root = inventory.occurrences.find(
      (row) => row.logical_path === ".",
    ).format_metadata;
    const blocks = included.flatMap((entry) =>
      entry.layout.map(([, name]) =>
        Math.ceil(files[name].length / entry.payload),
      ),
    );
    const blockCount = blocks.reduce((sum, count) => sum + count, 0);
    assert.deepEqual(
      {
        block_count: root.block_count,
        invalid_block_count: root.invalid_block_count,
        flash_block_count: root.flash_block_count,
        md5_block_count: root.md5_block_count,
        family_count: root.family_count,
        sequence_count: root.sequence_count,
        missing_block_count: root.missing_block_count,
        duplicate_bytes: root.duplicate_bytes,
      },
      {
        block_count: blockCount,
        invalid_block_count: 0,
        flash_block_count: blockCount,
        md5_block_count: included
          .filter((entry) => entry.md5)
          .flatMap((entry) =>
            entry.layout.map(([, name]) =>
              Math.ceil(files[name].length / entry.payload),
            ),
          )
          .reduce((sum, count) => sum + count, 0),
        family_count: included.length,
        sequence_count: blocks.length,
        missing_block_count: 0,
        duplicate_bytes: 0,
      },
      file,
    );
    const expected = included.flatMap((entry) =>
      entry.layout.map(([address, name]) => ({
        path: `${familyDirectory(entry.familyId)}/${hex32(address)}-${hex32(address + files[name].length - 1)}.bin`,
        familyId: entry.familyId,
        bytes: files[name],
      })),
    );
    const regions = inventory.occurrences.filter(
      (row) => row.format_metadata?.kind === "uf2-region",
    );
    assert.deepEqual(
      regions.map((row) => row.logical_path).sort(),
      expected.map((region) => region.path).sort(),
      file,
    );
    for (const region of regions)
      assert.equal(
        region.format_metadata.family_id,
        expected.find((row) => row.path === region.logical_path).familyId,
        `${file} ${region.logical_path}`,
      );
    const extracted = await rea("extract-artifact", path(file));
    assert.equal(extracted.containment_verified, true, file);
    for (const region of expected)
      assert.equal(
        Buffer.compare(
          await readFile(join(extracted.output_root, region.path)),
          region.bytes,
        ),
        0,
        `${file} ${region.path}`,
      );
    report.cases.push({
      file,
      families: included.map((entry) => ({
        chip: entry.chip,
        family_id: hex32(entry.familyId),
        family_name: regions.find(
          (row) => row.format_metadata.family_id === entry.familyId,
        ).format_metadata.family_name,
      })),
      blocks: blockCount,
      regions: regions.length,
      md5_blocks: root.md5_block_count,
    });
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}, [
  () => commands.close(),
  () =>
    workspace === undefined
      ? undefined
      : rm(workspace, { recursive: true, force: true }),
]);
