import { ESP_IMAGE_LIMITATIONS } from "../domain/firmware/espImageFacts.js";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it, vi } from "vitest";

import { EspImageArtifactReader } from "./EspImageArtifactReader.js";
import { ArtifactResourceScope } from "./ArtifactResourceScope.js";
import type { ArtifactEntry } from "./ArtifactReader.js";
import { extractArtifact } from "./extraction/ArtifactExtraction.js";
import * as espImageDecoding from "../domain/firmware/espImage.js";
import {
  ESP32C3_APP_SEGMENTS,
  ESP8266_SEGMENTS,
  esp8266Image,
  esp8266ImageOf,
  espImage,
  pattern,
  signedEspImage,
} from "../../tests/fixtures/espImage.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { scanCanonicalArtifactInventory } from "../../tests/fixtures/artifactInventory.js";
import { awaitAcknowledgement } from "../../tests/fixtures/lifecycleAcknowledgement.js";

const APP = espImage({ segments: ESP32C3_APP_SEGMENTS });
// An erased slot between two blocks must not hide the later block.
const SIGNED = signedEspImage(APP, ["rsa", null, "ecdsa-p256"]);

const writeImage = async (bytes: Uint8Array, name = "app.bin") => {
  const path = join(await createTestTempDirectory("rea-esp-image-"), name);
  await writeFile(path, bytes);
  return path;
};

const list = async (reader: EspImageArtifactReader) => {
  const entries: ArtifactEntry[] = [];
  for await (const entry of reader.entries()) entries.push(entry);
  return entries;
};

it("inventories segments and signature blocks with root and entry facts", async () => {
  const snapshot = await scanCanonicalArtifactInventory(
    await writeImage(SIGNED),
  );
  expect(snapshot.manifest.root_format).toBe("esp-image");
  expect(snapshot.coverage).toEqual({
    scope: "container-entries",
    status: "complete",
  });
  expect(snapshot.limitations).toEqual([ESP_IMAGE_LIMITATIONS.inventoryScope]);
  const root = snapshot.occurrences.find((row) => row.logical_path === ".");
  expect(root).toMatchObject({
    artifact_kind: "container",
    artifact_format: "esp-image",
    format_metadata: {
      kind: "esp-image",
      descriptor: { kind: "app" },
      chip: { target: "esp32c3", isa: "riscv" },
      checksum: { status: "valid" },
      appended_sha256: { status: "valid" },
      signature_sector_offset: 4096,
      undescribed_trailing: [],
    },
  });
  expect(
    snapshot.occurrences
      .filter((row) => row.logical_path !== ".")
      .map((row) => [
        row.logical_path,
        row.declared_size,
        row.source_location,
        row.hash_status,
        row.format_metadata?.kind,
      ]),
  ).toEqual([
    [
      "segment-00.bin",
      288,
      { offset: 32, length: 288 },
      "verified",
      "esp-image-segment",
    ],
    [
      "segment-01.bin",
      16,
      { offset: 328, length: 16 },
      "verified",
      "esp-image-segment",
    ],
    [
      "segment-02.bin",
      32,
      { offset: 352, length: 32 },
      "verified",
      "esp-image-segment",
    ],
    [
      "segment-03.bin",
      64,
      { offset: 392, length: 64 },
      "verified",
      "esp-image-segment",
    ],
    [
      "signature-block-0.bin",
      1216,
      { offset: 4096, length: 1216 },
      "verified",
      "esp-image-signature-block",
    ],
    [
      "signature-block-2.bin",
      1216,
      { offset: 6528, length: 1216 },
      "verified",
      "esp-image-signature-block",
    ],
  ]);
  expect(
    snapshot.occurrences.find((row) => row.logical_path === "segment-03.bin")
      ?.format_metadata,
  ).toEqual({
    kind: "esp-image-segment",
    index: 3,
    load_addr: 0x4200_0020,
    data_len: 64,
    header_offset: 384,
    classification: "mapped",
  });
});

it("reports truncation and undescribed trailing bytes as coverage", async () => {
  const bytes = APP.subarray(0, 360);
  const truncated = await scanCanonicalArtifactInventory(
    await writeImage(bytes),
  );
  expect(truncated.manifest.root_format).toBe("esp-image");
  expect(truncated.coverage.status).toBe("unknown");
  const decoder = espImageDecoding.createEspImageDecoder(bytes.length);
  decoder.write(bytes);
  const decoded = decoder.finish();
  if (!decoded.ok)
    throw new Error("Expected partial fixture facts", { cause: decoded.error });
  expect(truncated.limitations).toEqual(
    expect.arrayContaining([
      ESP_IMAGE_LIMITATIONS.inventoryScope,
      ...decoded.value.limitations,
    ]),
  );
  const segment = truncated.occurrences.find(
    (row) => row.logical_path === "segment-02.bin",
  );
  expect(segment).toMatchObject({
    declared_size: 8,
    limitations: [ESP_IMAGE_LIMITATIONS.segmentEntryTruncated(2, 32, 8)],
    source_location: { offset: 352, length: 8 },
    format_metadata: {
      kind: "esp-image-segment",
      index: 2,
      header_offset: 344,
      data_len: 32,
    },
  });
  const extended = await scanCanonicalArtifactInventory(
    await writeImage(Buffer.concat([APP, Buffer.from("trailing data")])),
  );
  expect(extended.coverage.status).toBe("unknown");
  expect(
    extended.occurrences.find((row) => row.logical_path === ".")
      ?.format_metadata,
  ).toMatchObject({
    undescribed_trailing: [{ offset: APP.length, length: 13 }],
  });
});

it("extracts byte-exact segments that re-inventory as raw files", async () => {
  const directory = await createTestTempDirectory("rea-esp-extract-");
  const path = join(directory, "signed.bin");
  await writeFile(path, SIGNED);
  const resourceScope = new ArtifactResourceScope();
  try {
    const extracted = await extractArtifact({
      inputPath: path,
      inputFormat: "esp-image",
      outputRoot: join(directory, "out"),
      environment: process.env,
      integrityPolicy: "fail",
      resourceScope,
    });
    expect(extracted.containment_verified).toBe(true);
    expect(extracted.artifacts.map((row) => row.relative_path).sort()).toEqual([
      "segment-00.bin",
      "segment-01.bin",
      "segment-02.bin",
      "segment-03.bin",
      "signature-block-0.bin",
      "signature-block-2.bin",
    ]);
    for (const [name, offset, length] of [
      ["segment-00.bin", 32, 288],
      ["segment-03.bin", 392, 64],
      ["signature-block-0.bin", 4096, 1216],
      ["signature-block-2.bin", 6528, 1216],
    ] as const)
      expect(
        Buffer.compare(
          await readFile(join(extracted.output_root, name)),
          SIGNED.subarray(offset, offset + length),
        ),
      ).toBe(0);
    const reinventoried = await scanCanonicalArtifactInventory(
      extracted.output_root,
    );
    expect(reinventoried.manifest.root_format).toBe("directory");
  } finally {
    await resourceScope.close();
  }
});

it("refuses an ESP8266 image with its specific reason", async () => {
  const reader = new EspImageArtifactReader(
    await writeImage(esp8266Image(), "esp8266.bin"),
  );
  try {
    await expect(list(reader)).rejects.toMatchObject({
      reason: "unavailable",
      message: espImageDecoding.ESP8266_REFUSAL,
    });
  } finally {
    await reader.close();
  }
});

// A NONOS SDK 0x00000.bin followed by erased flash and an unrelated record.
const ESP8266_DUMP = Buffer.concat([
  esp8266ImageOf({ segments: ESP8266_SEGMENTS }),
  Buffer.alloc(16, 0xff),
  pattern(16, 3),
]);

it("inventories an ESP8266 image only when the caller names the chip", async () => {
  const path = await writeImage(ESP8266_DUMP, "esp8266.bin");
  const snapshot = await scanCanonicalArtifactInventory(path, {
    selectedRootFormat: "esp8266-image",
  });
  expect(snapshot.manifest.root_format).toBe("esp8266-image");
  expect(snapshot.coverage).toEqual({
    scope: "container-entries",
    status: "unknown",
  });
  expect(snapshot.limitations).toEqual(
    expect.arrayContaining([
      ESP_IMAGE_LIMITATIONS.esp8266InventoryScope,
      ESP_IMAGE_LIMITATIONS.esp8266UndescribedTrailing(16, 96),
    ]),
  );
  expect(
    snapshot.occurrences.find((row) => row.logical_path === "."),
  ).toMatchObject({
    artifact_kind: "container",
    artifact_format: "esp8266-image",
    format_metadata: {
      kind: "esp8266-image",
      checksum: { status: "valid" },
      image_end: 80,
      undescribed_trailing: [{ offset: 96, length: 16 }],
    },
  });
  expect(
    snapshot.occurrences
      .filter((row) => row.logical_path !== ".")
      .map((row) => [
        row.logical_path,
        row.source_location,
        row.hash_status,
        row.format_metadata,
      ]),
  ).toEqual([
    [
      "segment-00.bin",
      { offset: 16, length: 32 },
      "verified",
      {
        kind: "esp-image-segment",
        index: 0,
        load_addr: 0x4010_0000,
        data_len: 32,
        header_offset: 8,
        classification: "unknown",
      },
    ],
    [
      "segment-01.bin",
      { offset: 56, length: 16 },
      "verified",
      {
        kind: "esp-image-segment",
        index: 1,
        load_addr: 0x3ffe_8000,
        data_len: 16,
        header_offset: 48,
        classification: "unknown",
      },
    ],
  ]);
  // Without the caller's chip, inventory does not read the bytes as an image.
  const detected = await scanCanonicalArtifactInventory(path);
  expect(detected.manifest.root_format).not.toMatch(/^esp/u);
  expect(detected.occurrences).toHaveLength(1);
});

it("refuses a named ESP8266 image whose header does not admit one", async () => {
  await expect(
    scanCanonicalArtifactInventory(await writeImage(pattern(64, 0x5a)), {
      selectedRootFormat: "esp8266-image",
    }),
  ).rejects.toMatchObject({
    reason: "format",
    message: expect.stringContaining("ESP8266 image header needs magic 0xe9"),
  });
  const v2 = Buffer.from(ESP8266_DUMP);
  v2[0] = 0xea;
  await expect(
    scanCanonicalArtifactInventory(await writeImage(v2), {
      selectedRootFormat: "esp8266-image",
    }),
  ).rejects.toMatchObject({ reason: "unavailable" });
});

it("extracts byte-exact ESP8266 segments", async () => {
  const directory = await createTestTempDirectory("rea-esp8266-extract-");
  const path = join(directory, "esp8266.bin");
  await writeFile(path, ESP8266_DUMP);
  const resourceScope = new ArtifactResourceScope();
  try {
    const extracted = await extractArtifact({
      inputPath: path,
      inputFormat: "esp8266-image",
      outputRoot: join(directory, "out"),
      environment: process.env,
      integrityPolicy: "fail",
      resourceScope,
    });
    expect(extracted.containment_verified).toBe(true);
    expect(extracted.artifacts.map((row) => row.relative_path).sort()).toEqual([
      "segment-00.bin",
      "segment-01.bin",
    ]);
    for (const [name, offset, length] of [
      ["segment-00.bin", 16, 32],
      ["segment-01.bin", 56, 16],
    ] as const)
      expect(
        Buffer.compare(
          await readFile(join(extracted.output_root, name)),
          ESP8266_DUMP.subarray(offset, offset + length),
        ),
      ).toBe(0);
  } finally {
    await resourceScope.close();
  }
});

it("reads ESP8266 root metadata through the reader it names", async () => {
  const reader = new EspImageArtifactReader(
    await writeImage(ESP8266_DUMP, "esp8266.bin"),
    undefined,
    "esp8266-image",
  );
  try {
    expect(reader.format).toBe("esp8266-image");
    expect((await list(reader)).map((entry) => entry.path)).toEqual([
      "segment-00.bin",
      "segment-01.bin",
    ]);
    expect(reader.formatMetadata()).toMatchObject({
      kind: "esp8266-image",
      header: { segment_count: 2, entry_addr: 0x4010_0004 },
    });
  } finally {
    await reader.close();
  }
});

it("rejects a changed carrier during extraction preparation", async () => {
  const reader = new EspImageArtifactReader(await writeImage(APP));
  try {
    await expect(reader.prepareContainer("0".repeat(64))).rejects.toMatchObject(
      { reason: "integrity" },
    );
  } finally {
    await reader.close();
  }
});

it("rejects forged entries and changed carrier identity, then closes idempotently", async () => {
  const path = await writeImage(APP);
  const reader = new EspImageArtifactReader(path);
  try {
    const [entry] = await list(reader);
    if (entry === undefined) throw new Error("Missing segment");
    await expect(
      reader.open({ ...entry, declaredSize: 1 }),
    ).rejects.toMatchObject({ reason: "integrity" });
    await expect(
      reader.open({ ...entry, byteOffset: 0 }),
    ).rejects.toMatchObject({ reason: "integrity" });
    await expect(
      reader.open({ ...entry, adapterKey: "esp-image:segment:9" }),
    ).rejects.toMatchObject({ reason: "integrity" });
    await writeFile(path, APP.subarray(0, 300));
    await expect(reader.open(entry)).rejects.toMatchObject({
      reason: "integrity",
    });
  } finally {
    await reader.close();
    await reader.close();
  }
});

it("settles an active entry stream when closed", async () => {
  const reader = new EspImageArtifactReader(await writeImage(APP));
  try {
    const [entry] = await list(reader);
    if (entry === undefined) throw new Error("Missing segment");
    const stream = await reader.open(entry);
    await reader.close();
    expect(stream.destroyed).toBe(true);
    await expect(
      reader.entries()[Symbol.asyncIterator]().next(),
    ).rejects.toMatchObject({ reason: "unavailable" });
  } finally {
    await reader.close();
  }
});

it("honors cancellation before admitting a file with the exact reason", async () => {
  const reader = new EspImageArtifactReader(await writeImage(APP));
  const controller = new AbortController();
  const reason = { stage: "before admission" };
  controller.abort(reason);
  try {
    await expect(
      reader.entries(controller.signal)[Symbol.asyncIterator]().next(),
    ).rejects.toMatchObject({ reason: "cancelled", cause: reason });
  } finally {
    await reader.close();
  }
});

it.each(["cancel", "close"] as const)(
  "settles decoding when the caller requests %s",
  async (action) => {
    // Several MiB of segment data take many chunked reads to decode.
    const large = espImage({
      segments: [{ address: 0x4038_0000, data: Buffer.alloc(8 << 20, 0x5a) }],
    });
    const reader = new EspImageArtifactReader(await writeImage(large));
    const controller = new AbortController();
    const reason = { stage: "decoding" };
    let completion: Promise<void> | undefined;
    let pending: Promise<unknown> | undefined;
    // The decoder acknowledges its first chunk, so the request arrives while
    // decoding is active rather than while the file is still being admitted.
    let decoded = 0;
    let acknowledge = (): void => undefined;
    const decoding = new Promise<void>((resolve) => {
      acknowledge = resolve;
    });
    const create = espImageDecoding.createEspImageDecoder;
    const observer = vi
      .spyOn(espImageDecoding, "createEspImageDecoder")
      .mockImplementation((size) => {
        const decoder = create(size);
        return {
          write: (chunk) => {
            decoder.write(chunk);
            decoded += 1;
            acknowledge();
          },
          get satisfied() {
            return decoder.satisfied;
          },
          finish: () => decoder.finish(),
        };
      });
    try {
      pending = reader
        .entries(controller.signal)
        [Symbol.asyncIterator]()
        .next();
      await awaitAcknowledgement(decoding, pending, "ESP image decoding");
      const requestedAt = decoded;
      if (action === "cancel") controller.abort(reason);
      else completion = reader.close();
      await expect(pending).rejects.toMatchObject(
        action === "cancel"
          ? { reason: "cancelled", cause: reason }
          : { reason: "unavailable" },
      );
      await completion;
      // The request stops decoding; no later chunk reaches the decoder.
      expect(decoded).toBe(requestedAt);
      await reader.close();
      await expect(
        reader.entries()[Symbol.asyncIterator]().next(),
      ).rejects.toMatchObject({ reason: "unavailable" });
    } finally {
      try {
        await reader.close();
      } finally {
        await pending?.catch(() => undefined);
        observer.mockRestore();
      }
    }
  },
);
