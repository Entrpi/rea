import { z } from "zod";

import {
  espFlashImageMetadataSchema,
  offset,
  uint8,
  uint32,
  type ArtifactFormatMetadata,
  type EspFlashImageMetadata,
} from "../artifactFormatMetadata.js";

type EspFlashImageFacts = NonNullable<
  EspFlashImageMetadata["bootloader"]
>["facts"];

/**
 * One ESP image in a flash layout's summary view. The complete Evidence
 * keeps its full facts, segments and signature blocks included.
 */
const espImageSummarySchema = z.strictObject({
  status: z.enum(["esp-image", "erased", "unrecognized"]),
  /** The chip target, from the header's `chip_id`; null when unknown. */
  chip: z.string().nullable(),
  entry_addr: uint32.nullable(),
  /** The header's segment count. */
  segment_count: uint8.nullable(),
  /** Where each segment that is mapped, loaded or unclassified goes. */
  load_ranges: z.array(z.strictObject({ address: uint32, length: uint32 })),
  checksum: z.enum(["valid", "invalid", "unavailable"]).nullable(),
  appended_sha256: z
    .enum(["valid", "invalid", "unavailable", "not-appended"])
    .nullable(),
  coverage: z.enum(["complete", "unknown"]).nullable(),
  limitations: z.array(z.string()),
});

/**
 * An ESP flash layout's root facts in the summary view: each nested image
 * is a `summary` instead of its full `facts`.
 */
export const espFlashImageSummaryMetadataSchema =
  espFlashImageMetadataSchema.extend({
    bootloader: z
      .strictObject({
        flash_address: uint32,
        region_size: offset,
        summary: espImageSummarySchema,
      })
      .nullable(),
    apps: z.array(
      z.strictObject({
        partition_index: uint8,
        summary: espImageSummarySchema,
      }),
    ),
  });
export type EspFlashImageSummaryMetadata = z.infer<
  typeof espFlashImageSummaryMetadataSchema
>;

const summarizeImage = (
  facts: EspFlashImageFacts,
): z.infer<typeof espImageSummarySchema> => ({
  status: facts.status,
  chip: facts.image?.chip?.target ?? null,
  entry_addr: facts.image?.header.entry_addr ?? null,
  segment_count: facts.image?.header.segment_count ?? null,
  load_ranges: facts.segments
    .filter(({ classification }) => classification !== "not-loaded")
    .map(({ load_addr: address, data_len: length }) => ({ address, length })),
  checksum: facts.image?.checksum.status ?? null,
  appended_sha256: facts.image?.appended_sha256.status ?? null,
  coverage: facts.coverage,
  limitations: [...facts.limitations],
});

/** Root facts for the summary view: compact for an ESP flash layout. */
export const summaryRootMetadata = (
  metadata: ArtifactFormatMetadata,
): ArtifactFormatMetadata | EspFlashImageSummaryMetadata => {
  if (metadata.kind !== "esp-flash-image") return metadata;
  const { bootloader, apps, ...rest } = metadata;
  return {
    ...rest,
    bootloader:
      bootloader === null
        ? null
        : {
            flash_address: bootloader.flash_address,
            region_size: bootloader.region_size,
            summary: summarizeImage(bootloader.facts),
          },
    apps: apps.map(({ partition_index, facts }) => ({
      partition_index,
      summary: summarizeImage(facts),
    })),
  };
};
