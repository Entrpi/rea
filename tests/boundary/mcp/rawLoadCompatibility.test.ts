import { McpServer } from "@modelcontextprotocol/server";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { parseConfig } from "../../../src/config/parseConfig.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import {
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
} from "../../../src/domain/rawBinary.fixture.js";
import { ghidraProfileInstallationHost as host } from "../../../src/ghidra/GhidraInstallation.fixture.js";
import { attestGhidraRawBinaryLoadImage } from "../../../src/ghidra/GhidraLoadImageValues.js";
import { GhidraProvider } from "../../../src/ghidra/GhidraProvider.js";
import {
  armBxLrImage,
  fixtureRawBinaryLoadImage,
  m6809Image,
} from "../../../src/ghidra/GhidraRawBinaryLoadImage.fixture.js";
import { silentLogger } from "../../../src/logger.js";
import { toolRegistrationOptions } from "../../../src/server/toolRegistrationOptions.js";
import { cortexM0Fixture } from "../../conformance/ghidra/cortexM.fixture.mjs";
import { mcpTest } from "../../support/mcp/mcpFixture.js";

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

// One image holds the vector table and the Thumb code its Reset word names;
// the load is admitted from these bytes.
const segmentsImage = () => {
  const bytes = cortexM0Fixture(0x08000000);
  const rawLoad = admittedRawLoad(
    {
      architecture: "arm",
      architectureVariant: "armv7-m",
      entryPoint: undefined,
      baseAddress: "0x8000000",
      fileBytes: bytes.length,
    },
    bytes.subarray(0, 8),
  );
  const f = fixtureRawBinaryLoadImage(bytes, rawLoad);
  f.observation.entry_context = [
    {
      address: rawLoad.entryPoint,
      registers: [{ name: "TMode", value_hex: "0x1" }],
    },
  ];
  const image = attestGhidraRawBinaryLoadImage(
    f.snapshot,
    f.target,
    f.observation,
  );
  if (!image.ok) throw new Error(image.error);
  if (image.value.status !== "verified")
    throw new Error("the segments image fixture does not verify");
  return { target: f.target, image: image.value };
};

describe("raw-binary loads without the M-profile inputs", () => {
  it("keep the target selection and profile they had before those inputs", async () => {
    const bytes = armBxLrImage();
    const { target } = fixtureRawBinaryLoadImage(
      bytes,
      admittedRawLoad({
        architecture: "arm",
        entryPoint: "0x08000000",
        fileBytes: bytes.length,
      }),
    );
    // A legacy load selects its entry only, as before these inputs.
    expect(snapshotTarget(target).identity.selection).toStrictEqual({
      kind: "entry-point",
      entry_point: "0x8000000",
    });
    const parameters = (await ghidraProfile(target)).parameters;
    expect(parameters).toMatchObject({ entry_point: "0x8000000" });
    for (const key of ["raw_load", "entry_context", "processor_labels"])
      expect(parameters).not.toHaveProperty(key);
  });

  it("are not the target or profile of an M-profile load of the same file", async () => {
    const bytes = armBxLrImage();
    const legacy = fixtureRawBinaryLoadImage(
      bytes,
      admittedRawLoad({
        architecture: "arm",
        entryPoint: "0x08000000",
        fileBytes: bytes.length,
      }),
    ).target;
    const variant = fixtureRawBinaryLoadImage(
      bytes,
      admittedRawLoad({
        architecture: "arm",
        architectureVariant: "armv7-m",
        baseAddress: "0x8000000",
        entryPoint: "0x8000000",
        fileBytes: bytes.length,
      }),
    ).target;
    expect(snapshotMatchesTarget(snapshotTarget(legacy), variant)).toBe(false);
    expect((await ghidraProfile(variant)).digest).not.toBe(
      (await ghidraProfile(legacy)).digest,
    );
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
    "advertises output that accepts raw-binary and segments images",
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
          fixtureRawBinaryLoadImage().target,
          { id: "ghidra", name: "Ghidra", version: "12.2" },
          { operation: contract.name, parameters: {}, result },
        );
      const f = fixtureRawBinaryLoadImage();
      const legacyImage = attestGhidraRawBinaryLoadImage(
        f.snapshot,
        f.target,
        f.observation,
      );
      if (!legacyImage.ok) throw new Error(legacyImage.error);
      const saved = jsonValueSchema.parse(legacyImage.value);
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

// One 6809 image at a separate base; the load is admitted for these bytes.
const providerLanguageImage = () => {
  const bytes = m6809Image();
  const f = fixtureRawBinaryLoadImage(
    bytes,
    providerLanguageRawTarget(
      {
        provider: "ghidra",
        languageId: "6809:BE:16:default",
        compilerSpecId: "default",
      },
      { baseAddress: "0xe000", entryPoint: "0xe000", fileBytes: bytes.length },
    ).rawLoad,
  );
  const image = attestGhidraRawBinaryLoadImage(
    f.snapshot,
    f.target,
    f.observation,
  );
  if (!image.ok) throw new Error(image.error);
  return { target: f.target, image: image.value };
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
    const selection = snapshotTarget(target).identity.selection;
    if (selection?.kind !== "entry-point" || selection.raw_load === undefined)
      throw new Error("expected a raw load identity");
    expect(
      rawLoadIdentitySchema
        .omit({ provider_language: true })
        .safeParse(selection.raw_load).success,
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
            providerLanguageImage().target,
            { id: "ghidra", name: "Ghidra", version: "12.2" },
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
