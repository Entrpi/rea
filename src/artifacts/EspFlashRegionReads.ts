import type { FileHandle } from "node:fs/promises";

import type { EspFlashImageMetadata } from "../domain/artifactFormatMetadata.js";
import type { EspFlashWrittenExtent } from "../domain/firmware/espFlashLayout.js";
import {
  ESP8266_REFUSAL,
  createEspImageDecoder,
  recognizeEspImage,
} from "../domain/firmware/espImage.js";
import { firstUnerased } from "../domain/firmware/espImageStructures.js";
import { readFileHandleChunks } from "../filesystem/readFileHandleChunks.js";
import { ArtifactReaderFailure } from "./ArtifactReader.js";

const LABEL = "ESP flash image";
const HEADER_BYTES = 24;
const PROBE_BYTES = 32;

/** The carrier being read, its size and the caller's cancellation. */
export interface EspFlashReadContext {
  readonly handle: FileHandle;
  readonly fileSize: number;
  readonly signal?: AbortSignal | undefined;
}

type EspFlashImageFacts = NonNullable<
  EspFlashImageMetadata["bootloader"]
>["facts"];

const chunks = (
  { handle, signal }: EspFlashReadContext,
  start: number,
  length: number,
): AsyncIterable<Buffer> =>
  readFileHandleChunks(handle, {
    start,
    end: start + length - 1,
    signal,
    cancellationFailure: (reason) =>
      new ArtifactReaderFailure("cancelled", `${LABEL} read cancelled`, {
        cause: reason,
      }),
  }) as AsyncIterable<Buffer>;

/** Up to `length` bytes at a file offset; fewer at the end of the file. */
export const readEspFlashRange = async (
  context: EspFlashReadContext,
  position: number,
  length: number,
): Promise<Buffer> => {
  const available = Math.min(length, context.fileSize - position);
  if (position < 0 || available <= 0) return Buffer.alloc(0);
  const parts: Buffer[] = [];
  for await (const chunk of chunks(context, position, available))
    parts.push(chunk);
  return Buffer.concat(parts);
};

/** The file offset of the first byte in a range that is not erased flash. */
export const firstUnerasedInRange = async (
  context: EspFlashReadContext,
  start: number,
  length: number,
): Promise<number | undefined> => {
  if (length <= 0) return undefined;
  let position = start;
  for await (const chunk of chunks(context, start, length)) {
    const found = firstUnerased(chunk, position);
    if (found !== undefined) return found;
    position += chunk.length;
  }
  return undefined;
};

/** Read every byte of a region once and find where it is not erased. */
export const writtenExtent = async (
  context: EspFlashReadContext,
  region: { readonly start: number; readonly length: number },
  assertOpen: () => void,
): Promise<EspFlashWrittenExtent> => {
  let first = -1;
  let last = -1;
  let bytes = 0;
  let position = 0;
  if (region.length > 0)
    for await (const chunk of chunks(context, region.start, region.length)) {
      assertOpen();
      for (let index = 0; index < chunk.length; index += 1)
        if (chunk[index] !== 0xff) {
          bytes += 1;
          last = position + index;
          if (first < 0) first = last;
        }
      position += chunk.length;
    }
  return first < 0
    ? { offset: null, end: null, bytes: 0 }
    : { offset: first, end: last + 1, bytes };
};

const noImage = (
  status: "erased" | "unrecognized",
  limitations: readonly string[],
): EspFlashImageFacts => ({
  status,
  image: null,
  segments: [],
  signature_blocks: [],
  coverage: null,
  limitations: [...limitations],
});

/**
 * Decode an ESP image at the start of a region, as the bootloader reads a
 * partition: one streaming pass with the ESP image decoder. Offsets in the
 * facts are relative to the region; `erased` means the header bytes are
 * erased flash.
 */
export const decodeEspFlashImage = async (
  context: EspFlashReadContext,
  region: { readonly start: number; readonly length: number },
  assertOpen: () => void,
): Promise<EspFlashImageFacts> => {
  // The region's end bounds the read, so a short region stays short.
  const prefix = await readEspFlashRange(
    { ...context, fileSize: region.start + region.length },
    region.start,
    PROBE_BYTES,
  );
  // A region shorter than a header is erased when all of its bytes are.
  if (
    prefix.length > 0 &&
    prefix.subarray(0, HEADER_BYTES).every((byte) => byte === 0xff)
  )
    return noImage("erased", []);
  const recognized = recognizeEspImage(prefix, region.length);
  if (recognized === "esp8266")
    return noImage("unrecognized", [ESP8266_REFUSAL]);
  if (recognized !== "esp-image")
    return noImage("unrecognized", [
      "The region does not begin with a recognized ESP image header; it may be encrypted or hold other data.",
    ]);
  const decoder = createEspImageDecoder(region.length);
  for await (const chunk of chunks(context, region.start, region.length)) {
    assertOpen();
    decoder.write(chunk);
    if (decoder.satisfied) break;
  }
  const image = decoder.finish();
  if (!image.ok) return noImage("unrecognized", [image.error.message]);
  return {
    status: "esp-image",
    image: image.value.metadata,
    segments: image.value.segments.map(({ metadata }) => ({ ...metadata })),
    signature_blocks: image.value.signatureBlocks.map(({ metadata }) => ({
      ...metadata,
    })),
    coverage: image.value.coverage,
    limitations: [...image.value.limitations],
  };
};
