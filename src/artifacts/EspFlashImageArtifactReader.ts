import type { FileHandle } from "node:fs/promises";

import type { EspFlashImageMetadata } from "../domain/artifactFormatMetadata.js";
import { ESP_CHIP_TABLE_SOURCE } from "../domain/firmware/espChips.js";
import {
  espFlashPartitionFacts,
  finishEspFlashLayout,
  planEspFlashLayout,
  type EspFlashLayoutFacts,
  type EspFlashPlan,
  type EspFlashRegion,
} from "../domain/firmware/espFlashLayout.js";
import {
  locateEspFlashLayout,
  type EspFlashLocation,
  type EspFlashSelection,
} from "../domain/firmware/espFlashLocation.js";
import { offsetText } from "../domain/firmware/espImageStructures.js";
import { ESP_OTA_SELECT_ENTRY_BYTES } from "../domain/firmware/espOtaData.js";
import { isEspAppPartition } from "../domain/firmware/espPartitionTable.js";
import { ArtifactReaderFailure } from "./ArtifactReader.js";
import {
  decodeEspFlashImage,
  firstUnerasedInRange,
  readEspFlashRange,
  type EspFlashReadContext,
} from "./EspFlashRegionReads.js";
import {
  PositionalArtifactReader,
  type PositionalArtifactEntries,
  type PositionalArtifactEntry,
} from "./PositionalArtifactReader.js";
import type { StableRegularFileDescriptor } from "../filesystem/RegularFile.js";

const LABEL = "ESP flash image";

/** A located layout borrowed with the descriptor that produced it. */
export interface EspFlashAdmission {
  readonly kind: "esp-flash-image";
  readonly source: StableRegularFileDescriptor;
  readonly location: EspFlashLocation;
}

type EspFlashImageFacts = NonNullable<
  EspFlashImageMetadata["bootloader"]
>["facts"];

/**
 * Inventory an ESP flash dump as its bootloader region, partition table and
 * partitions. The bootloader and app partitions are decoded as ESP images;
 * each entry is a positional read of the carrier, rechecked against its
 * identity.
 */
export class EspFlashImageArtifactReader extends PositionalArtifactReader {
  override readonly format = "esp-flash-image" as const;
  readonly #located: EspFlashLocation | undefined;
  readonly #selection: EspFlashSelection;
  #metadata: EspFlashImageMetadata | undefined;

  constructor(
    path: string,
    admitted?: EspFlashAdmission | StableRegularFileDescriptor,
    selection: EspFlashSelection = {},
  ) {
    const admission =
      admitted !== undefined && "kind" in admitted ? admitted : undefined;
    super(
      path,
      LABEL,
      admission?.source ??
        (admitted as StableRegularFileDescriptor | undefined),
    );
    this.#located = admission?.location;
    this.#selection = selection;
  }

  formatMetadata(): EspFlashImageMetadata | undefined {
    return this.#metadata === undefined
      ? undefined
      : structuredClone(this.#metadata);
  }

  protected override async prepareEntries(
    signal?: AbortSignal,
  ): Promise<PositionalArtifactEntries> {
    const { handle, initial } = await this.verifyCarrier(signal);
    const fileSize = initial.size;
    const location =
      this.#located ?? (await this.#locate(handle, fileSize, signal));
    const plan = planEspFlashLayout({
      fileSize,
      origin: location.origin,
      bootloader: location.bootloader,
      tableAddress: location.tableAddress,
      tableMethod: location.tableMethod,
      table: location.table,
    });
    const context: EspFlashReadContext = { handle, fileSize, signal };
    const facts = await this.#readFacts(context, plan);
    const images = await this.#decodeImages(context, plan);
    // A changed carrier is an identity failure, not a different layout.
    await this.verifyCarrier(signal);
    this.#metadata = layoutMetadata(location, plan, facts, images);
    const limitations = [
      ...location.limitations,
      ...(location.tableMethod === "scan"
        ? [
            `The partition table at ${offsetText(location.tableAddress)} was found by scanning 0x1000-aligned flash sectors for a table whose MD5 verifies; the dump does not record the bootloader's configured table offset.`,
          ]
        : []),
      ...facts.limitations,
    ];
    return {
      entries: plan.regions.map(regionEntry),
      coverage:
        facts.coverage === "unknown" || limitations.length > 0
          ? { status: facts.coverage, limitations }
          : undefined,
    };
  }

  async #locate(
    handle: FileHandle,
    fileSize: number,
    signal?: AbortSignal,
  ): Promise<EspFlashLocation> {
    const located = await locateEspFlashLayout(
      fileSize,
      (position, length) =>
        readEspFlashRange({ handle, fileSize, signal }, position, length),
      this.#selection,
      { explicit: true, ...(signal === undefined ? {} : { signal }) },
    );
    if (!located.ok)
      throw new ArtifactReaderFailure(
        "unavailable",
        `${LABEL} layout is not recognized: ${located.error}`,
      );
    return located.value;
  }

  async #readFacts(
    context: EspFlashReadContext,
    plan: EspFlashPlan,
  ): Promise<EspFlashLayoutFacts> {
    const otadataRecords: (Uint8Array | undefined)[] = [];
    for (const { fileOffset, available } of plan.otadata?.records ?? [])
      otadataRecords.push(
        available
          ? await readEspFlashRange(
              context,
              fileOffset,
              ESP_OTA_SELECT_ENTRY_BYTES,
            )
          : undefined,
      );
    const gapFirstUnerased: (number | undefined)[] = [];
    for (const gap of plan.gaps) {
      this.assertOpen(context.signal);
      gapFirstUnerased.push(
        await firstUnerasedInRange(context, gap.offset, gap.length),
      );
    }
    return finishEspFlashLayout(plan, { otadataRecords, gapFirstUnerased });
  }

  /** ESP image facts for the bootloader region and each app partition. */
  async #decodeImages(
    context: EspFlashReadContext,
    plan: EspFlashPlan,
  ): Promise<ReadonlyMap<EspFlashRegion, EspFlashImageFacts>> {
    const images = new Map<EspFlashRegion, EspFlashImageFacts>();
    for (const region of plan.regions) {
      const image =
        region.role === "bootloader" ||
        (region.partition !== undefined && isEspAppPartition(region.partition));
      if (!image) continue;
      this.assertOpen(context.signal);
      images.set(
        region,
        await decodeEspFlashImage(
          context,
          { start: region.fileOffset, length: region.available },
          () => this.assertOpen(context.signal),
        ),
      );
    }
    return images;
  }
}

/** One positional entry; a partition's declared flags stay metadata. */
const regionEntry = (region: EspFlashRegion): PositionalArtifactEntry => ({
  path: region.path,
  ...(region.partition?.label === null || region.partition === undefined
    ? {}
    : { sourcePath: region.partition.label }),
  kind: "file",
  declaredSize: region.available,
  compressedSize: null,
  executable: false,
  // The table's encrypted flag says how a device stores the partition, not
  // that these bytes are ciphertext.
  encrypted: false,
  byteOffset: region.fileOffset,
  declaredIntegrity: null,
  unpacked: false,
  limitations:
    region.available < region.length
      ? [
          `${region.path} is truncated: the dump holds ${String(region.available)} of its ${String(region.length)} bytes.`,
        ]
      : [],
  adapterKey: `esp-flash-image:${region.path}`,
  ...(region.partition === undefined
    ? {}
    : { formatMetadata: espFlashPartitionFacts(region.partition) }),
});

const layoutMetadata = (
  location: EspFlashLocation,
  plan: EspFlashPlan,
  facts: EspFlashLayoutFacts,
  images: ReadonlyMap<EspFlashRegion, EspFlashImageFacts>,
): EspFlashImageMetadata => {
  const bootloaderRegion = plan.regions.find(
    ({ role }) => role === "bootloader",
  );
  const bootloaderFacts =
    bootloaderRegion === undefined ? undefined : images.get(bootloaderRegion);
  const placed = new Set(
    plan.regions.flatMap(({ partition }) =>
      partition === undefined ? [] : [partition.index],
    ),
  );
  const { bootloader, table } = location;
  return {
    kind: "esp-flash-image",
    flash_offset: location.origin,
    chip:
      bootloader === undefined
        ? null
        : {
            target: bootloader.chip.target,
            isa: bootloader.chip.isa,
            source: ESP_CHIP_TABLE_SOURCE,
          },
    bootloader:
      bootloaderRegion === undefined || bootloaderFacts === undefined
        ? null
        : {
            flash_address: bootloaderRegion.flashAddress,
            region_size: bootloaderRegion.length,
            facts: bootloaderFacts,
          },
    partition_table: {
      flash_address: location.tableAddress,
      method: location.tableMethod,
      partition_count: table.partitions.length,
      md5: {
        status: table.md5.status,
        stored: table.md5.stored,
        computed: table.md5.computed,
      },
    },
    partitions_outside_dump: table.partitions
      .filter(({ index }) => !placed.has(index))
      .map(espFlashPartitionFacts),
    apps: [...images].flatMap(([region, image]) =>
      region.partition === undefined
        ? []
        : [{ partition_index: region.partition.index, facts: image }],
    ),
    otadata:
      facts.otadata === null
        ? null
        : {
            ...facts.otadata,
            records: facts.otadata.records.map((record) => ({ ...record })),
            selected:
              facts.otadata.selected === null
                ? null
                : {
                    ...facts.otadata.selected,
                    assumptions: [...facts.otadata.selected.assumptions],
                  },
          },
    undescribed: [...facts.undescribed],
  };
};
