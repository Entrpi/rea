import { Readable, Transform, pipeline } from "node:stream";
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
import {
  ArtifactReaderFailure,
  copyArtifactEntry,
  sameArtifactEntry,
  type ArtifactEntry,
  type ArtifactReader,
  type ArtifactReaderTraversal,
  type ArtifactTraversalOptions,
} from "./ArtifactReader.js";
import { ArtifactResourceScope } from "./ArtifactResourceScope.js";
import { assertArtifactReadActive } from "./ArtifactFileOperation.js";
import { ArtifactFileSource } from "./ArtifactFileSource.js";
import {
  decodeEspFlashImage,
  firstUnerasedInRange,
  readEspFlashRange,
  type EspFlashReadContext,
} from "./EspFlashRegionReads.js";
import { readFileHandleChunks } from "../filesystem/readFileHandleChunks.js";
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
export class EspFlashImageArtifactReader implements ArtifactReader {
  readonly format = "esp-flash-image" as const;
  readonly #scope = new ArtifactResourceScope();
  readonly #entries = new Map<string, ArtifactEntry>();
  readonly #streams = new Set<Readable>();
  readonly #source: ArtifactFileSource;
  readonly #located: EspFlashLocation | undefined;
  readonly #selection: EspFlashSelection;
  #prepared: Promise<void> | undefined;
  #metadata: EspFlashImageMetadata | undefined;
  #coverage: ArtifactReaderTraversal | undefined;
  #closing = false;

  constructor(
    path: string,
    admitted?: EspFlashAdmission | StableRegularFileDescriptor,
    selection: EspFlashSelection = {},
  ) {
    const admission =
      admitted !== undefined && "kind" in admitted ? admitted : undefined;
    this.#source = new ArtifactFileSource(
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

  async prepareContainer(
    expectedSha256: string,
    signal?: AbortSignal,
  ): Promise<void> {
    await this.#scope.run(async () => {
      this.#assertOpen(signal);
      await this.#source.bindSha256(expectedSha256, signal);
    });
  }

  async *entries(
    signal?: AbortSignal,
    options?: ArtifactTraversalOptions,
  ): AsyncIterable<ArtifactEntry> {
    await this.#scope.run(async () => {
      this.#assertOpen(signal);
      this.#prepared ??= this.#prepare(signal);
      await this.#prepared;
      await this.#source.read(signal);
    });
    if (this.#coverage !== undefined)
      options?.onCoverage?.({
        ...this.#coverage,
        limitations: [...this.#coverage.limitations],
      });
    for (const entry of this.#entries.values()) {
      this.#assertOpen(signal);
      yield copyArtifactEntry(entry);
    }
  }

  async open(entry: ArtifactEntry, signal?: AbortSignal): Promise<Readable> {
    return this.#scope.run(async () => {
      this.#assertOpen(signal);
      const stored = this.#entries.get(entry.adapterKey);
      if (
        stored === undefined ||
        !sameArtifactEntry(entry, stored) ||
        stored.byteOffset === null ||
        stored.declaredSize === null
      )
        throw new ArtifactReaderFailure(
          "integrity",
          `${LABEL} entry does not match its owning inventory`,
        );
      const { handle } = await this.#source.read(signal);
      this.#assertOpen(signal);
      const source =
        stored.declaredSize === 0
          ? Readable.from([])
          : readFileHandleChunks(handle, {
              start: stored.byteOffset,
              end: stored.byteOffset + stored.declaredSize - 1,
              signal,
              cancellationFailure: (reason) =>
                new ArtifactReaderFailure(
                  "cancelled",
                  `${LABEL} read cancelled`,
                  { cause: reason },
                ),
            });
      const output = this.#entryStream(stored, signal);
      // Retirement can destroy the stream before its consumer listens.
      output.on("error", () => undefined);
      this.#streams.add(output);
      output.once("close", () => this.#streams.delete(output));
      void this.#scope
        .run(
          () =>
            new Promise<void>((resolve) => {
              pipeline(source, output, () => {
                resolve();
              });
            }),
        )
        .catch((cause: unknown) =>
          output.destroy(
            cause instanceof Error
              ? cause
              : new Error(`${LABEL} stream ownership failed`, { cause }),
          ),
        );
      return output;
    });
  }

  async close(): Promise<void> {
    this.#closing = true;
    for (const stream of this.#streams)
      stream.destroy(
        new ArtifactReaderFailure("unavailable", `${LABEL} reader closed`),
      );
    await this.#scope.close();
    await this.#source.close();
    this.#entries.clear();
  }

  provenance(): readonly [] {
    return [];
  }

  #assertOpen(signal?: AbortSignal): void {
    assertArtifactReadActive(signal);
    if (this.#closing)
      throw new ArtifactReaderFailure(
        "unavailable",
        `${LABEL} reader is closed`,
      );
  }

  async #prepare(signal?: AbortSignal): Promise<void> {
    const { handle, initial } = await this.#source.read(signal);
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
    await this.#source.read(signal);
    for (const region of plan.regions) {
      const entry = regionEntry(region);
      this.#entries.set(entry.adapterKey, entry);
    }
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
    if (facts.coverage === "unknown" || limitations.length > 0)
      this.#coverage = { status: facts.coverage, limitations };
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
    const record = (position: number) =>
      readEspFlashRange(context, position, ESP_OTA_SELECT_ENTRY_BYTES);
    const otadataRecords =
      plan.otadata === undefined
        ? undefined
        : ([
            await record(plan.otadata.records[0]),
            await record(plan.otadata.records[1]),
          ] as const);
    const gapFirstUnerased: (number | undefined)[] = [];
    for (const gap of plan.gaps) {
      this.#assertOpen(context.signal);
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
      this.#assertOpen(context.signal);
      images.set(
        region,
        await decodeEspFlashImage(
          context,
          { start: region.fileOffset, length: region.available },
          () => this.#assertOpen(context.signal),
        ),
      );
    }
    return images;
  }

  #entryStream(entry: ArtifactEntry, signal?: AbortSignal): Transform {
    let bytes = 0;
    const check = async (): Promise<void> => {
      if (bytes !== entry.declaredSize)
        throw new ArtifactReaderFailure(
          "integrity",
          `${LABEL} entry ended early: ${entry.path}`,
        );
      await this.#source.read(signal);
    };
    return new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        bytes += chunk.length;
        callback(null, chunk);
      },
      flush(callback) {
        void check().then(
          () => callback(),
          (cause: unknown) =>
            callback(
              cause instanceof Error
                ? cause
                : new Error(`${LABEL} read failed`, { cause }),
            ),
        );
      },
    });
  }
}

/** One positional entry; a partition's declared flags stay metadata. */
const regionEntry = (region: EspFlashRegion): ArtifactEntry => ({
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
            selected: {
              ...facts.otadata.selected,
              assumptions: [...facts.otadata.selected.assumptions],
            },
          },
    undescribed: [...facts.undescribed],
  };
};
