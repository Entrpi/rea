import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { z } from "zod";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import {
  ESP32C3_BOOTLOADER_SEGMENTS,
  espImage,
} from "../../../src/domain/firmware/espImage.fixture.js";
import { espFlashDump } from "../../../src/domain/firmware/espFlash.fixture.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import {
  artifactExtractionResultSchema,
  artifactInventoryResultSchema,
} from "../../../src/domain/artifactGraph.js";
import { artifactInspectionResultSchema } from "../../../src/domain/artifactInspection.js";

const summarySchema = z.object({
  summary: z.object({ root_format_metadata: z.unknown() }),
});

const completeBootloaderSchema = z.object({
  bootloader: z.object({
    facts: z.object({
      segments: z.array(
        z.object({
          load_addr: z.number(),
          data_len: z.number(),
          classification: z.string(),
        }),
      ),
    }),
  }),
});

// The compiled stdio fixture checks advertised schemas against their dialect
// and validates actual tool responses.
it.each(["full", "compact"] as const)(
  "reads a flash dump at the caller's origin and keeps inputs in its identity (%s)",
  async (profile) => {
    const root = await createTestTempDirectory("rea-esp-flash-mcp-");
    const path = join(root, "from-0x1000.bin");
    const esp32 = espImage({
      segments: ESP32C3_BOOTLOADER_SEGMENTS,
      chipId: 0x0000,
    });
    const dump = espFlashDump({ bootloader: { at: 0x1000, bytes: esp32 } });
    await writeFile(path, dump.subarray(0x1000));
    const { call } = await connectLocalToolsMcp({
      REA_MCP_INPUT_SCHEMA_PROFILE: profile,
    });
    let outputRoot: string | undefined;
    try {
      const rejected = await call("open_binary", {
        path,
        flash_offset: "0x1000",
      });
      expect(rejected.isError).toBe(true);
      expect(JSON.stringify(rejected)).toContain(
        "flash_offset and partition_table_offset apply only with format=esp-flash-image",
      );
      const opened = await call("open_binary", {
        path,
        format: "esp-flash-image",
        flash_offset: "0x1000",
      });
      expect(opened.isError, JSON.stringify(opened)).not.toBe(true);
      expect(JSON.stringify(opened.structuredContent)).toContain(
        '"partition_table_offset":null',
      );
      const reply = await call("inspect_artifact", { detail: "summary" });
      expect(reply.isError, JSON.stringify(reply)).not.toBe(true);
      const summaryRoot = summarySchema.parse(
        parseEvidence(reply.structuredContent).normalized_result,
      ).summary.root_format_metadata;
      expect(summaryRoot).toMatchObject({
        kind: "esp-flash-image",
        flash_offset: { value: 0x1000, source: "caller" },
        chip: { target: "esp32" },
        partition_table: { flash_address: 0x8000, method: "default" },
      });
      // The summary view gives each image's summary; complete keeps segments.
      const complete = await call("inspect_artifact", {});
      expect(complete.isError, JSON.stringify(complete)).not.toBe(true);
      const { facts } = completeBootloaderSchema.parse(
        artifactInventoryResultSchema
          .parse(
            artifactInspectionResultSchema.parse(
              parseEvidence(complete.structuredContent).normalized_result,
            ).substeps[0]?.evidence.normalized_result,
          )
          .occurrences.find(({ logical_path }) => logical_path === ".")
          ?.format_metadata,
      ).bootloader;
      expect(facts.segments).toHaveLength(ESP32C3_BOOTLOADER_SEGMENTS.length);
      expect(summaryRoot).toMatchObject({
        bootloader: {
          flash_address: 0x1000,
          summary: {
            status: "esp-image",
            chip: "esp32",
            segment_count: ESP32C3_BOOTLOADER_SEGMENTS.length,
            load_ranges: facts.segments
              .filter(({ classification }) => classification !== "not-loaded")
              .map(({ load_addr, data_len }) => ({
                address: load_addr,
                length: data_len,
              })),
            checksum: "valid",
          },
        },
      });
      expect(JSON.stringify(summaryRoot)).not.toContain('"segments"');
      const extracted = await call("extract_artifact", {});
      expect(extracted.isError, JSON.stringify(extracted)).not.toBe(true);
      const result = artifactExtractionResultSchema.parse(
        parseEvidence(extracted.structuredContent).normalized_result,
      );
      outputRoot = result.output_root;
      // nvs at flash 0x9000 is file offset 0x8000 in a dump read from 0x1000.
      expect(
        Buffer.compare(
          await readFile(join(result.output_root, "partitions/nvs.bin")),
          dump.subarray(0x9000, 0xd000),
        ),
      ).toBe(0);
      // Reopening the same bytes with other inputs is a different target.
      const reopened = await call("open_binary", {
        path,
        format: "esp-flash-image",
        flash_offset: "0x1000",
        partition_table_offset: "0x8000",
      });
      expect(reopened.isError, JSON.stringify(reopened)).not.toBe(true);
      const again = await call("inspect_artifact", { detail: "summary" });
      expect(
        summarySchema.parse(
          parseEvidence(again.structuredContent).normalized_result,
        ).summary.root_format_metadata,
      ).toMatchObject({ partition_table: { method: "caller" } });
    } finally {
      if (outputRoot !== undefined)
        await rm(outputRoot, { recursive: true, force: true });
    }
  },
);
