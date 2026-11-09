import type {
  Esp8266ImageMetadata,
  EspImageMetadata,
} from "../domain/artifactFormatMetadata.js";
import { espChipForId } from "../domain/firmware/espChips.js";
import {
  espFlashDumpOrigin,
  type EspFlashDumpOrigin,
} from "../domain/firmware/espFlashLocation.js";
import {
  createEsp8266ImageDecoder,
  createEspImageDecoder,
  type EspImageDecoder,
  type EspImageFailure,
} from "../domain/firmware/espImage.js";
import {
  ESP_IMAGE_LIMITATIONS,
  type EspImage,
} from "../domain/firmware/espImageFacts.js";
import {
  ESP_SIGNATURE_BLOCK_BYTES,
  offsetText,
} from "../domain/firmware/espImageStructures.js";
import { ArtifactReaderFailure } from "./ArtifactReader.js";
import { readEspFlashRange } from "./EspFlashRegionReads.js";
import {
  PositionalArtifactReader,
  type PositionalArtifactEntries,
  type PositionalArtifactEntry,
} from "./PositionalArtifactReader.js";
import { readFileHandleChunks } from "../filesystem/readFileHandleChunks.js";
import type { StableRegularFileDescriptor } from "../filesystem/RegularFile.js";

/** ESP32-family images, or images whose caller named the ESP8266 chip. */
type EspImageReaderFormat = "esp-image" | "esp8266-image";
type EspImageReaderMetadata = EspImageMetadata | Esp8266ImageMetadata;

/**
 * Inventory one ESP image as its header-declared segments and, for an
 * ESP32-family image, its Secure Boot v2 signature blocks. Decoding reads the
 * file once; each entry is a positional read of the carrier, rechecked
 * against its identity.
 */
export class EspImageArtifactReader extends PositionalArtifactReader {
  override readonly format: EspImageReaderFormat;
  /** How messages name the image the caller selected. */
  readonly #label: string;
  #metadata: EspImageReaderMetadata | undefined;

  constructor(
    path: string,
    admitted?: StableRegularFileDescriptor,
    format: EspImageReaderFormat = "esp-image",
  ) {
    const label = format === "esp8266-image" ? "ESP8266 image" : "ESP image";
    super(path, label, admitted);
    this.format = format;
    this.#label = label;
  }

  formatMetadata(): EspImageReaderMetadata | undefined {
    return this.#metadata === undefined
      ? undefined
      : structuredClone(this.#metadata);
  }

  protected override async prepareEntries(
    signal?: AbortSignal,
  ): Promise<PositionalArtifactEntries> {
    const image = await this.#decode(signal);
    const entries: PositionalArtifactEntry[] = [];
    for (const segment of image.segments) {
      const { index, data_len } = segment.metadata;
      const entry = {
        path: `segment-${String(index).padStart(2, "0")}.bin`,
        kind: "file" as const,
        declaredSize: segment.availableLength,
        compressedSize: null,
        executable: false,
        encrypted: false,
        byteOffset: segment.dataOffset,
        declaredIntegrity: null,
        unpacked: false,
        limitations:
          segment.availableLength < data_len
            ? [
                ESP_IMAGE_LIMITATIONS.segmentEntryTruncated(
                  index,
                  data_len,
                  segment.availableLength,
                ),
              ]
            : [],
        adapterKey: `esp-image:segment:${String(index)}`,
        formatMetadata: { ...segment.metadata },
      } satisfies PositionalArtifactEntry;
      entries.push(entry);
    }
    for (const block of image.signatureBlocks) {
      const entry = {
        path: `signature-block-${String(block.metadata.index)}.bin`,
        kind: "file" as const,
        declaredSize: ESP_SIGNATURE_BLOCK_BYTES,
        compressedSize: null,
        executable: false,
        encrypted: false,
        byteOffset: block.offset,
        declaredIntegrity: null,
        unpacked: false,
        limitations: [],
        adapterKey: `esp-image:signature-block:${String(block.metadata.index)}`,
        formatMetadata: { ...block.metadata },
      } satisfies PositionalArtifactEntry;
      entries.push(entry);
    }
    const limitations = [...image.limitations];
    const { metadata } = image;
    if (metadata.kind === "esp8266-image") this.#metadata = metadata;
    else {
      // The flash-dump check reads the ESP32-family chip id and descriptor,
      // which an ESP8266 image header does not carry.
      const dump = await this.#flashDump(metadata, signal);
      this.#metadata = {
        ...metadata,
        flash_dump:
          dump === undefined
            ? null
            : {
                flash_offset: dump.flashOffset,
                table_file_offset: dump.tableFileOffset,
              },
      };
      if (dump !== undefined)
        limitations.push(flashDumpLimitation(metadata, dump));
    }
    return {
      entries,
      coverage:
        image.coverage === "unknown" || limitations.length > 0
          ? { status: image.coverage, limitations }
          : undefined,
    };
  }

  /**
   * Whether this image is the bootloader at the start of a flash dump read
   * from a later flash address. An app carries `esp_app_desc_t` and is not.
   */
  async #flashDump(
    metadata: EspImageMetadata,
    signal?: AbortSignal,
  ): Promise<EspFlashDumpOrigin | undefined> {
    const chip = espChipForId(metadata.header.chip_id);
    if (
      chip === undefined ||
      chip.romBootloaderOffset === 0 ||
      metadata.descriptor?.kind === "app"
    )
      return undefined;
    this.assertOpen(signal);
    const { handle, initial } = await this.verifyCarrier(signal);
    const context = { handle, fileSize: initial.size, signal };
    return espFlashDumpOrigin(
      (position, length) => readEspFlashRange(context, position, length),
      initial.size,
      // A truncated image has no end, so no table can follow it.
      { chip, fileOffset: 0, end: metadata.image_end ?? initial.size },
    );
  }

  /** Stream the carrier once, stopping when later bytes cannot matter. */
  async #decode(
    signal?: AbortSignal,
  ): Promise<EspImage<EspImageReaderMetadata>> {
    const { handle, initial } = await this.verifyCarrier(signal);
    const decoder: EspImageDecoder<EspImageReaderMetadata> =
      this.format === "esp8266-image"
        ? createEsp8266ImageDecoder(initial.size)
        : createEspImageDecoder(initial.size);
    if (initial.size > 0)
      for await (const chunk of readFileHandleChunks(handle, {
        end: initial.size - 1,
        signal,
        cancellationFailure: (reason) =>
          new ArtifactReaderFailure(
            "cancelled",
            `${this.#label} read cancelled`,
            { cause: reason },
          ),
      }) as AsyncIterable<Buffer>) {
        this.assertOpen(signal);
        decoder.write(chunk);
        if (decoder.satisfied) break;
      }
    // A changed carrier is an identity failure, not a malformed image.
    await this.verifyCarrier(signal);
    const image = decoder.finish();
    if (!image.ok) throw decodeFailure(image.error, this.#label);
    return image.value;
  }
}

const flashDumpLimitation = (
  metadata: EspImageMetadata,
  dump: EspFlashDumpOrigin,
): string =>
  `This file looks like a flash dump read from flash ${offsetText(dump.flashOffset)}, not one ESP image: its ${metadata.chip?.target ?? "ESP"} image at file offset 0 is where the ROM loads the bootloader from ${offsetText(dump.flashOffset)}, and a partition table sits at file offset ${offsetText(dump.tableFileOffset)}, which is flash 0x8000 from that origin. Reopen it with format esp-flash-image and flash_offset ${offsetText(dump.flashOffset)}.`;

const decodeFailure = (
  failure: EspImageFailure,
  label: string,
): ArtifactReaderFailure =>
  failure.kind === "unsupported"
    ? new ArtifactReaderFailure("unavailable", failure.message)
    : new ArtifactReaderFailure(
        "format",
        `${label} is malformed: ${failure.message}`,
      );
