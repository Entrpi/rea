import { describe, expect, it } from "vitest";

import {
  decodeEspPartitionTable,
  espPartitionSubtypeName,
  espPartitionTypeName,
  type EspPartition,
} from "./espPartitionTable.js";
import { decodeEspOtaRecord, selectEspOtaSlot } from "./espOtaData.js";
import {
  espBootloaderProbeOffsets,
  locateEspBootloader,
} from "./espFlashBootloader.js";
import {
  TWO_OTA_PARTITIONS,
  otaRecord,
  partitionEntry,
  partitionTable,
} from "./espFlash.fixture.js";
import { ESP32C3_BOOTLOADER_SEGMENTS, espImage } from "./espImage.fixture.js";

const table = (bytes: Uint8Array) => {
  const decoded = decodeEspPartitionTable(bytes);
  if (!decoded.ok) throw new Error(decoded.error);
  return decoded.value;
};

describe("ESP partition tables", () => {
  it("decodes entries, flags and a verified MD5 as gen_esp32part writes them", () => {
    const decoded = table(
      partitionTable([
        ...TWO_OTA_PARTITIONS,
        {
          label: "keys",
          type: 0x01,
          subtype: 0x04,
          offset: 0x4_0000,
          size: 0x1000,
          flags: 0b11,
        },
      ]),
    );
    expect(decoded.md5.status).toBe("valid");
    expect(decoded.md5.entryOffset).toBe(7 * 32);
    expect(decoded.length).toBe(9 * 32);
    expect(decoded.limitations).toEqual([]);
    expect(decoded.partitions.map(({ label }) => label)).toEqual([
      "nvs",
      "otadata",
      "phy_init",
      "factory",
      "ota_0",
      "ota_1",
      "keys",
    ]);
    expect(decoded.partitions.at(-1)).toMatchObject({
      index: 6,
      entryOffset: 6 * 32,
      type: 0x01,
      subtype: 0x04,
      offset: 0x4_0000,
      size: 0x1000,
      encrypted: true,
      readonly: true,
      unknownFlags: 0,
    });
  });

  it("accepts a table without an MD5 entry, as the bootloader does", () => {
    const decoded = table(
      partitionTable(TWO_OTA_PARTITIONS, { md5: "absent" }),
    );
    expect(decoded.md5).toEqual({
      status: "absent",
      entryOffset: null,
      stored: null,
      computed: null,
    });
    expect(decoded.partitions).toHaveLength(6);
  });

  it("keeps the entries of a table whose MD5 does not match", () => {
    const decoded = table(
      partitionTable(TWO_OTA_PARTITIONS, { md5: "corrupt" }),
    );
    expect(decoded.md5.status).toBe("invalid");
    expect(decoded.partitions).toHaveLength(6);
    expect(decoded.limitations).toEqual([
      "The partition table MD5 at 0xc0 does not match the entries before it; ESP-IDF's bootloader rejects the table.",
    ]);
  });

  it.each([
    ["erased flash", Buffer.alloc(0xc00, 0xff), "the first entry is empty"],
    [
      "a foreign entry",
      Buffer.concat([
        partitionEntry(TWO_OTA_PARTITIONS[0]!),
        Buffer.alloc(32, 0),
        Buffer.alloc(0xbc0, 0xff),
      ]),
      "entry 1 at 0x20 has magic 0x0, not a partition, MD5 or terminating entry",
    ],
    [
      "no terminator",
      Buffer.concat(
        Array.from({ length: 96 }, () =>
          partitionEntry(TWO_OTA_PARTITIONS[0]!),
        ),
      ),
      "no terminating entry within 96 entries (0xc00 bytes)",
    ],
    [
      "short bytes",
      partitionEntry(TWO_OTA_PARTITIONS[0]!),
      "the bytes end at 0x20, inside entry 1",
    ],
  ])("rejects %s as not a table", (_name, bytes, reason) => {
    expect(decodeEspPartitionTable(bytes)).toEqual({
      ok: false,
      error: reason,
    });
  });

  it("names types and subtypes as ESP-IDF does, and keeps unknown flags and labels", () => {
    expect(espPartitionTypeName(0x00)).toBe("app");
    expect(espPartitionSubtypeName(0x00, 0x1f)).toBe("ota_15");
    expect(espPartitionSubtypeName(0x01, 0x04)).toBe("nvs_keys");
    expect(espPartitionTypeName(0x40)).toBeNull();
    expect(espPartitionSubtypeName(0x40, 0x00)).toBeNull();
    const entry = partitionEntry({
      label: "x",
      type: 0x40,
      subtype: 0,
      offset: 0x1_0000,
      size: 0x1000,
      flags: 0x8000_0001,
    });
    entry.writeUInt8(0xff, 13);
    const [decoded] = table(
      Buffer.concat([entry, Buffer.alloc(0xbe0, 0xff)]),
    ).partitions;
    expect(decoded).toMatchObject({
      label: null,
      encrypted: true,
      unknownFlags: 0x8000_0000,
    });
  });
});

const partitions = (): readonly EspPartition[] =>
  table(partitionTable(TWO_OTA_PARTITIONS)).partitions;

describe("ESP otadata selection", () => {
  it("decodes records and checks the CRC the bootloader computes", () => {
    expect(
      decodeEspOtaRecord(otaRecord({ seq: 3, state: 2 }), 0),
    ).toMatchObject({
      index: 0,
      ota_seq: 3,
      ota_state: 2,
      state_name: "valid",
      crc_matches: true,
      valid: true,
    });
    expect(decodeEspOtaRecord(otaRecord({ seq: 3, crc: 0 }), 1)).toMatchObject({
      crc_matches: false,
      valid: false,
    });
    expect(decodeEspOtaRecord(Buffer.alloc(32, 0xff), 1)).toMatchObject({
      ota_seq: 0xffff_ffff,
      state_name: "undefined",
      valid: false,
    });
  });

  const select = (first: Buffer, second: Buffer, parts = partitions()) =>
    selectEspOtaSlot(
      [decodeEspOtaRecord(first, 0), decodeEspOtaRecord(second, 1)],
      parts,
    );
  const erased = Buffer.alloc(32, 0xff);

  it("selects the higher valid sequence and maps it onto the OTA slots", () => {
    expect(select(otaRecord({ seq: 4 }), otaRecord({ seq: 5 }))).toMatchObject({
      active_record: 1,
      slot: 0,
      partition_index: 4,
      basis: "otadata",
    });
    // An invalid state removes a record; a tie keeps record 0.
    expect(
      select(otaRecord({ seq: 6, state: 3 }), otaRecord({ seq: 5 })),
    ).toMatchObject({ active_record: 1, slot: 0 });
    expect(select(otaRecord({ seq: 2 }), otaRecord({ seq: 2 }))).toMatchObject({
      active_record: 0,
      slot: 1,
      partition_index: 5,
    });
  });

  it("falls back as the bootloader does without usable records", () => {
    expect(select(erased, erased)).toMatchObject({
      basis: "factory-fallback",
      partition_index: 3,
      slot: null,
    });
    const noFactory = partitions().filter(({ label }) => label !== "factory");
    expect(select(erased, erased, noFactory)).toMatchObject({
      basis: "ota_0-fallback",
      slot: 0,
      partition_index: 4,
    });
    // A set sequence with a bad CRC is not unusable, but no record is valid.
    expect(
      select(otaRecord({ seq: 2, crc: 1 }), erased, noFactory),
    ).toMatchObject({ basis: "none", partition_index: null });
    expect(select(otaRecord({ seq: 2 }), erased).assumptions).toHaveLength(3);
  });

  it("indexes OTA slots by subtype, so a missing subtype selects no partition", () => {
    const gapped = partitions().filter(({ label }) => label !== "ota_0");
    // Two OTA apps would be counted, but only ota_1 exists: seq 1 selects slot 0.
    const withSecond = [
      ...gapped,
      { ...gapped.at(-1)!, index: 9, subtype: 0x12, label: "ota_2" },
    ];
    expect(select(otaRecord({ seq: 1 }), erased, withSecond)).toMatchObject({
      slot: 0,
      partition_index: null,
      basis: "otadata",
    });
  });
});

describe("ESP bootloader location", () => {
  const bootloader = espImage({
    segments: ESP32C3_BOOTLOADER_SEGMENTS,
    chipId: 0x0005,
  });
  const probe = (flashAddress: number, bytes: Uint8Array) => ({
    flashAddress,
    fileOffset: flashAddress,
    prefix: bytes.subarray(0, 32),
    available: bytes.length,
  });

  it("locates the image at its chip's ROM offset", () => {
    expect(locateEspBootloader([probe(0, bootloader)])).toMatchObject({
      location: { flashAddress: 0, fileOffset: 0, chip: { target: "esp32c3" } },
      limitations: [],
    });
  });

  it("reports an image at another chip's ROM offset instead of locating it", () => {
    const esp32 = espImage({
      segments: ESP32C3_BOOTLOADER_SEGMENTS,
      chipId: 0x0000,
    });
    expect(locateEspBootloader([probe(0, esp32)])).toEqual({
      location: undefined,
      limitations: [
        "An esp32 image is at flash 0x0, but its ROM loads the bootloader from 0x1000; the dump may not start at the given flash offset.",
      ],
    });
  });

  it("probes only the ROM offsets the file holds after its flash offset", () => {
    expect(espBootloaderProbeOffsets(0, 0x10_0000)).toEqual([
      { flashAddress: 0, fileOffset: 0 },
      { flashAddress: 0x1000, fileOffset: 0x1000 },
      { flashAddress: 0x2000, fileOffset: 0x2000 },
    ]);
    expect(espBootloaderProbeOffsets(0x1000, 0x10_0000)).toEqual([
      { flashAddress: 0x1000, fileOffset: 0 },
      { flashAddress: 0x2000, fileOffset: 0x1000 },
    ]);
  });
});
