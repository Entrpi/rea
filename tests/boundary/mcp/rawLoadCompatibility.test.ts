import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { McpServer } from "@modelcontextprotocol/server";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { parseConfig } from "../../../src/config/parseConfig.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import {
  parseAnalysisSnapshot,
  snapshotEvidenceForQuery,
  snapshotMatchesBinding,
  snapshotMatchesTarget,
  snapshotTarget,
} from "../../../src/domain/analysisSnapshot.js";
import type { BinaryTarget } from "../../../src/domain/binaryTargetTypes.js";
import { createEvidence } from "../../../src/domain/evidence.js";
import {
  jsonValueSchema,
  type JsonValue,
} from "../../../src/domain/jsonValue.js";
import {
  nativeLoadImageSchema,
  nativeRawLoadImageSchema,
  nativeSegmentsLoadImageSchema,
} from "../../../src/domain/native/nativeLoadImage.js";
import {
  binaryArchitectureSchema,
  rawLoadIdentitySchema,
} from "../../../src/domain/rawBinary.js";
import {
  admittedRawLoad,
  providerLanguageRawTarget,
  vectorTableWords,
} from "../../../src/domain/rawBinary.fixture.js";
import { ghidraProfileInstallationHost as host } from "../../../src/ghidra/GhidraInstallation.fixture.js";
import { attestGhidraRawBinaryLoadImage } from "../../../src/ghidra/GhidraLoadImageValues.js";
import { GhidraProvider } from "../../../src/ghidra/GhidraProvider.js";
import { fixtureRawBinaryLoadImage } from "../../../src/ghidra/GhidraRawBinaryLoadImage.fixture.js";
import { silentLogger } from "../../../src/logger.js";
import { toolRegistrationOptions } from "../../../src/server/toolRegistrationOptions.js";
import { mcpTest } from "../../support/mcp/mcpFixture.js";

// Written by REA at d6f88becd, before base_address existed, from the raw ARM
// load-image fixture with its Ghidra profile. Never regenerate it: it stands
// for snapshots that callers already saved.
const HISTORICAL_SNAPSHOT =
  "tests/fixtures/snapshots/rawBinaryBeforeBaseAddress.json";

const historicalSnapshot = async () =>
  parseAnalysisSnapshot(
    JSON.parse(await readFile(resolve(HISTORICAL_SNAPSHOT), "utf8")),
  );

const ghidraProfile = async (target: BinaryTarget) => {
  const config = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra" });
  if (!config.ok) throw config.error;
  const resolved = await new GhidraProvider(
    config.value,
    silentLogger,
    {},
    host,
  ).resolveAnalysisProfile(target);
  if (!resolved.ok) throw resolved.error;
  if (resolved.value.profile === null) throw new Error("expected a profile");
  return resolved.value.profile;
};

const segmentsImage = () => {
  const f = fixtureRawBinaryLoadImage();
  const rawLoad = admittedRawLoad(
    {
      architecture: "arm",
      architectureVariant: "armv7-m",
      entryPoint: undefined,
      baseAddress: "0x8000000",
      fileBytes: 8,
    },
    vectorTableWords(0x20005000, 0x08000003),
  );
  const target = { ...f.target, rawLoad };
  f.observation.language_id = "ARM:LE:32:Cortex";
  f.observation.entry_points = [rawLoad.entryPoint];
  f.observation.entry_context = [
    {
      address: rawLoad.entryPoint,
      registers: [{ name: "TMode", value_hex: "0x1" }],
    },
  ];
  const image = attestGhidraRawBinaryLoadImage(
    f.snapshot,
    target,
    f.observation,
  );
  if (!image.ok) throw new Error(image.error);
  return { target, image: image.value };
};

describe("raw-binary snapshots saved before base_address", () => {
  it("replay for the same load admitted today", async () => {
    const snapshot = await historicalSnapshot();
    const f = fixtureRawBinaryLoadImage();
    const target = {
      ...f.target,
      rawLoad: admittedRawLoad({
        architecture: "arm",
        entryPoint: "0x08000000",
        fileBytes: 4,
      }),
    };
    const profile = await ghidraProfile(target);
    expect(snapshotMatchesTarget(snapshot.target, target)).toBe(true);
    expect(snapshotMatchesBinding(snapshot, target, profile)).toBe(true);
    const replayed = snapshotEvidenceForQuery(snapshot, {
      target,
      bindingProfile: profile,
      operation: "inspect_native_load_image",
      parameters: {},
      provider: profile.provider,
      evidenceProfile: profile,
    });
    if (replayed === undefined) throw new Error("snapshot did not replay");
    // The saved image still parses and equals what this version produces.
    const current = attestGhidraRawBinaryLoadImage(
      f.snapshot,
      f.target,
      f.observation,
    );
    if (!current.ok) throw new Error(current.error);
    expect(nativeLoadImageSchema.parse(replayed.normalized_result)).toEqual(
      current.value,
    );
  });

  it("does not replay for an M-profile load of the same file", async () => {
    const snapshot = await historicalSnapshot();
    const f = fixtureRawBinaryLoadImage();
    const target = {
      ...f.target,
      rawLoad: admittedRawLoad({
        architecture: "arm",
        architectureVariant: "armv7-m",
        entryPoint: "0x8000000",
        fileBytes: 4,
      }),
    };
    expect(snapshotMatchesTarget(snapshot.target, target)).toBe(false);
    expect(
      snapshotMatchesBinding(snapshot, target, await ghidraProfile(target)),
    ).toBe(false);
  });
});

describe("raw-binary load-image Evidence shapes", () => {
  it("keeps the earlier raw-binary shape closed to segments images", () => {
    // Readers that predate segments parse load images with this schema; they
    // refuse the new shape instead of misreading it as a raw-binary image.
    const { image } = segmentsImage();
    expect(nativeLoadImageSchema.safeParse(image).success).toBe(true);
    expect(nativeRawLoadImageSchema.safeParse(image).success).toBe(false);
    expect(
      nativeLoadImageSchema.safeParse({ ...image, version: 2 }).success,
    ).toBe(false);
  });

  mcpTest(
    "advertises output that accepts saved and segments images",
    async ({ mcp }) => {
      const contract = toolContract("inspect_native_load_image");
      const server = new McpServer({ name: "raw-load-images", version: "1" });
      server.registerTool(
        contract.name,
        toolRegistrationOptions(contract),
        async () => ({ content: [] }),
      );
      const client = await mcp.connect(server);
      const advertised = (await client.listTools()).tools.find(
        ({ name }) => name === contract.name,
      );
      if (advertised?.outputSchema === undefined)
        throw new Error("Load-image output schema missing");
      const ajv = new Ajv2020({ strict: false, validateFormats: false });
      const validate = ajv.compile(
        z.record(z.string(), z.unknown()).parse(advertised.outputSchema),
      );
      const evidence = (result: JsonValue) =>
        createEvidence(
          undefined,
          { id: "ghidra", name: "Ghidra", version: "12.1.4" },
          { operation: contract.name, parameters: {}, result },
        );
      const saved = (await historicalSnapshot()).entries[0]?.execution.result;
      if (saved === undefined) throw new Error("fixture has no entry");
      const image = jsonValueSchema.parse(segmentsImage().image);
      expect(validate(evidence(saved))).toBe(true);
      expect(validate(evidence(image))).toBe(true);
      expect(
        validate(
          evidence(
            jsonValueSchema.parse({ ...segmentsImage().image, version: 2 }),
          ),
        ),
      ).toBe(false);
    },
  );
});

describe("open_binary inputs from before base_address", () => {
  mcpTest(
    "stay valid in the advertised input schema beside the new inputs",
    async ({ mcp }) => {
      const contract = toolContract("open_binary");
      const server = new McpServer({ name: "raw-load-inputs", version: "1" });
      server.registerTool(
        contract.name,
        toolRegistrationOptions(contract),
        async () => ({ content: [] }),
      );
      const client = await mcp.connect(server);
      const advertised = (await client.listTools()).tools.find(
        ({ name }) => name === contract.name,
      );
      if (advertised === undefined) throw new Error("open_binary missing");
      const ajv = new Ajv2020({ strict: false, validateFormats: false });
      const validate = ajv.compile(
        z.record(z.string(), z.unknown()).parse(advertised.inputSchema),
      );
      const legacy = {
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x8000000",
      };
      expect(validate(legacy)).toBe(true);
      expect(
        validate({
          path: "/tmp/flash.bin",
          format: "raw-binary",
          architecture: "arm",
          architecture_variant: "armv8-m.main",
          base_address: "0x08000000",
          vector_table_address: "0x08000200",
        }),
      ).toBe(true);
      expect(validate({ ...legacy, architecture_variant: "cortex-m" })).toBe(
        false,
      );
    },
  );
});

const providerLanguageImage = () => {
  const f = fixtureRawBinaryLoadImage();
  const target = providerLanguageRawTarget(
    {
      provider: "ghidra",
      languageId: "6809:BE:16:default",
      compilerSpecId: "default",
    },
    {
      baseAddress: "0xe000",
      entryPoint: "0xe000",
      fileBytes: f.snapshot.bytes,
      sha256: f.target.sha256,
    },
  );
  const mapping = f.observation.mappings[0];
  if (mapping === undefined) throw new Error("Missing source mapping fixture");
  mapping.start = "0xe000";
  mapping.end = "0xe003";
  f.observation.language_id = "6809:BE:16:default";
  f.observation.entry_points = ["0xe000"];
  const image = attestGhidraRawBinaryLoadImage(
    f.snapshot,
    target,
    f.observation,
  );
  if (!image.ok) throw new Error(image.error);
  return { target, image: image.value };
};

describe("provider-language shapes beside earlier readers", () => {
  it("are refused by the segments and raw_load readers that predate them", () => {
    // Readers before provider_language required a family in segments images
    // and admitted no other raw_load key; they refuse these instead of
    // misreading them.
    const { target, image } = providerLanguageImage();
    expect(nativeLoadImageSchema.safeParse(image).success).toBe(true);
    expect(
      nativeSegmentsLoadImageSchema
        .extend({ architecture: binaryArchitectureSchema })
        .safeParse(image).success,
    ).toBe(false);
    const identity = snapshotTarget(target);
    if (identity.format !== "raw-binary" || identity.raw_load === undefined)
      throw new Error("expected a raw load identity");
    expect(
      rawLoadIdentitySchema
        .omit({ provider_language: true })
        .safeParse(identity.raw_load).success,
    ).toBe(false);
  });

  mcpTest(
    "are advertised to MCP clients as input and output",
    async ({ mcp }) => {
      const server = new McpServer({ name: "provider-language", version: "1" });
      for (const name of [
        "open_binary",
        "inspect_native_load_image",
      ] as const) {
        const contract = toolContract(name);
        server.registerTool(
          contract.name,
          toolRegistrationOptions(contract),
          async () => ({ content: [] }),
        );
      }
      const client = await mcp.connect(server);
      const tools = (await client.listTools()).tools;
      const ajv = new Ajv2020({ strict: false, validateFormats: false });
      const schema = (name: string, key: "inputSchema" | "outputSchema") =>
        ajv.compile(
          z
            .record(z.string(), z.unknown())
            .parse(tools.find((tool) => tool.name === name)?.[key]),
        );
      const input = schema("open_binary", "inputSchema");
      const selection = {
        path: "/tmp/firmware.bin",
        format: "raw-binary",
        provider_language: {
          provider: "ghidra",
          language_id: "SuperH4:LE:32:default",
          compiler_spec_id: "default",
        },
        base_address: "0x8c000000",
        entry_point: "0x8c000010",
        provider_id: "ghidra",
      };
      expect(input(selection)).toBe(true);
      expect(
        input({
          ...selection,
          provider_language: {
            ...selection.provider_language,
            provider: "ida",
          },
        }),
      ).toBe(false);
      const output = schema("inspect_native_load_image", "outputSchema");
      expect(
        output(
          createEvidence(
            undefined,
            { id: "ghidra", name: "Ghidra", version: "12.1.4" },
            {
              operation: "inspect_native_load_image",
              parameters: {},
              result: providerLanguageImage().image,
            },
          ),
        ),
      ).toBe(true);
    },
  );
});
