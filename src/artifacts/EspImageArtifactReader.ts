import type { EspImageMetadata } from "../domain/artifactFormatMetadata.js";
import {
  createEspImageDecoder,
  type EspImageFailure,
} from "../domain/firmware/espImage.js";
import type { EspImage } from "../domain/firmware/espImageFacts.js";
import { ESP_SIGNATURE_BLOCK_BYTES } from "../domain/firmware/espImageStructures.js";
import { ArtifactReaderFailure } from "./ArtifactReader.js";
import {
  PositionalArtifactReader,
  type PositionalArtifactEntries,
  type PositionalArtifactEntry,
} from "./PositionalArtifactReader.js";
import { readFileHandleChunks } from "../filesystem/readFileHandleChunks.js";
import type { StableRegularFileDescriptor } from "../filesystem/RegularFile.js";

const LABEL = "ESP image";

/**
 * Inventory one ESP32-family image as its header-declared segments and
 * Secure Boot v2 signature blocks. Decoding reads the file once; each entry
 * is a positional read of the carrier, rechecked against its identity.
 */
export class EspImageArtifactReader extends PositionalArtifactReader {
  override readonly format = "esp-image" as const;
  #metadata: EspImageMetadata | undefined;

  constructor(path: string, admitted?: StableRegularFileDescriptor) {
    super(path, LABEL, admitted);
  }

  formatMetadata(): EspImageMetadata | undefined {
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
                `ESP image segment ${String(index)} is truncated: its header declares ${String(data_len)} bytes; the file holds ${String(segment.availableLength)}.`,
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
    this.#metadata = image.metadata;
    return {
      entries,
      coverage:
        image.coverage === "unknown" || image.limitations.length > 0
          ? { status: image.coverage, limitations: [...image.limitations] }
          : undefined,
    };
  }

  /** Stream the carrier once, stopping when later bytes cannot matter. */
  async #decode(signal?: AbortSignal): Promise<EspImage> {
    const { handle, initial } = await this.verifyCarrier(signal);
    const decoder = createEspImageDecoder(initial.size);
    if (initial.size > 0)
      for await (const chunk of readFileHandleChunks(handle, {
        end: initial.size - 1,
        signal,
        cancellationFailure: (reason) =>
          new ArtifactReaderFailure("cancelled", `${LABEL} read cancelled`, {
            cause: reason,
          }),
      }) as AsyncIterable<Buffer>) {
        this.assertOpen(signal);
        decoder.write(chunk);
        if (decoder.satisfied) break;
      }
    // A changed carrier is an identity failure, not a malformed image.
    await this.verifyCarrier(signal);
    const image = decoder.finish();
    if (!image.ok) throw decodeFailure(image.error);
    return image.value;
  }
}

const decodeFailure = (failure: EspImageFailure): ArtifactReaderFailure =>
  failure.kind === "unsupported"
    ? new ArtifactReaderFailure("unavailable", failure.message)
    : new ArtifactReaderFailure(
        "format",
        `${LABEL} is malformed: ${failure.message}`,
      );
