import { createHash } from "node:crypto";

import { err, ok, type Result } from "../result.js";
import { hex, offsetText, u16, u32 } from "./espImageStructures.js";

/*
 * The partition table, from ESP-IDF v6.1 `esp_flash_partitions.h`,
 * `bootloader_support/src/flash_partitions.c` (`esp_partition_table_verify`,
 * which the bootloader applies) and `partition_table/gen_esp32part.py`.
 */
export const ESP_PARTITION_TABLE_DEFAULT_OFFSET = 0x8000;
/** The table occupies one flash sector (`ESP_PARTITION_TABLE_SIZE`). */
export const ESP_PARTITION_TABLE_SECTOR_BYTES = 0x1000;
/** `ESP_PARTITION_TABLE_MAX_LEN`: 96 entries, the MD5 and the terminator included. */
export const ESP_PARTITION_TABLE_MAX_BYTES = 0xc00;
const ENTRY_BYTES = 32;
const MAX_ENTRIES = ESP_PARTITION_TABLE_MAX_BYTES / ENTRY_BYTES;
const PARTITION_MAGIC = 0x50aa;
const MD5_MAGIC = 0xebeb;
const END_MAGIC = 0xffff;
const END_TYPE = 0xff;
/** `ESP_PARTITION_MD5_OFFSET`: the digest follows 16 bytes into its entry. */
const MD5_DIGEST_OFFSET = 16;
const KNOWN_FLAGS = 0b11;

/** One `esp_partition_info_t`, as the table declares it. */
export interface EspPartition {
  /** Position among the partition entries; the MD5 entry is not counted. */
  readonly index: number;
  /** Byte offset of the entry from the start of the table. */
  readonly entryOffset: number;
  readonly type: number;
  readonly subtype: number;
  /** Flash address. */
  readonly offset: number;
  readonly size: number;
  /** The label up to its first NUL, or null when it is not UTF-8. */
  readonly label: string | null;
  readonly encrypted: boolean;
  readonly readonly: boolean;
  /** Flag bits other than `encrypted` and `readonly`, which ESP-IDF ignores. */
  readonly unknownFlags: number;
}

export interface EspPartitionTableMd5 {
  readonly status: "valid" | "invalid" | "absent";
  readonly entryOffset: number | null;
  readonly stored: string | null;
  readonly computed: string | null;
}

export interface EspPartitionTable {
  readonly partitions: readonly EspPartition[];
  readonly md5: EspPartitionTableMd5;
  /** Bytes through the terminating entry. */
  readonly length: number;
  readonly limitations: readonly string[];
}

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const label = (bytes: Uint8Array): string | null => {
  const end = bytes.indexOf(0);
  try {
    return UTF8.decode(end < 0 ? bytes : bytes.subarray(0, end));
  } catch {
    return null;
  }
};

const partition = (
  entry: Uint8Array,
  index: number,
  entryOffset: number,
): EspPartition => {
  const flags = u32(entry, 28);
  return {
    index,
    entryOffset,
    type: entry[2] ?? 0,
    subtype: entry[3] ?? 0,
    offset: u32(entry, 4),
    size: u32(entry, 8),
    label: label(entry.subarray(12, 28)),
    encrypted: (flags & 1) !== 0,
    readonly: (flags & 2) !== 0,
    unknownFlags: (flags & ~KNOWN_FLAGS) >>> 0,
  };
};

/**
 * Decode a table as ESP-IDF's bootloader verifies it: 32-byte entries with
 * the `0x50AA` magic, at most one `0xEBEB` MD5 entry over the entries before
 * it, and a terminator whose magic, type and subtype are all `0xFF`, which
 * cannot be the first entry. A structural fault means the bytes are not a
 * table; an MD5 mismatch, which the bootloader also rejects, is reported as
 * an integrity fact so that the declared entries stay visible.
 */
export const decodeEspPartitionTable = (
  bytes: Uint8Array,
): Result<EspPartitionTable, string> => {
  const partitions: EspPartition[] = [];
  const limitations: string[] = [];
  let md5: EspPartitionTableMd5 = {
    status: "absent",
    entryOffset: null,
    stored: null,
    computed: null,
  };
  for (let slot = 0; slot < MAX_ENTRIES; slot += 1) {
    const at = slot * ENTRY_BYTES;
    const entry = bytes.subarray(at, at + ENTRY_BYTES);
    if (entry.length < ENTRY_BYTES)
      return err(
        `the bytes end at ${offsetText(at + entry.length)}, inside entry ${String(slot)}`,
      );
    const magic = u16(entry, 0);
    if (magic === PARTITION_MAGIC) {
      partitions.push(partition(entry, partitions.length, at));
      continue;
    }
    if (magic === MD5_MAGIC) {
      const computed = createHash("md5")
        .update(bytes.subarray(0, at))
        .digest("hex");
      const stored = hex(entry.subarray(MD5_DIGEST_OFFSET, ENTRY_BYTES));
      if (md5.status !== "absent") {
        limitations.push(
          `The partition table has a second MD5 entry at ${offsetText(at)}; ESP-IDF allows one and rejects the table.`,
        );
        md5 = { ...md5, status: "invalid" };
        continue;
      }
      md5 = {
        status: stored === computed ? "valid" : "invalid",
        entryOffset: at,
        stored,
        computed,
      };
      if (stored !== computed)
        limitations.push(
          `The partition table MD5 at ${offsetText(at)} does not match the entries before it; ESP-IDF's bootloader rejects the table.`,
        );
      continue;
    }
    if (
      slot > 0 &&
      magic === END_MAGIC &&
      entry[2] === END_TYPE &&
      entry[3] === END_TYPE
    )
      return ok({ partitions, md5, length: at + ENTRY_BYTES, limitations });
    return err(
      slot === 0 && magic === END_MAGIC
        ? "the first entry is empty"
        : `entry ${String(slot)} at ${offsetText(at)} has magic ${offsetText(magic)}, not a partition, MD5 or terminating entry`,
    );
  }
  return err(
    `no terminating entry within ${String(MAX_ENTRIES)} entries (${offsetText(ESP_PARTITION_TABLE_MAX_BYTES)} bytes)`,
  );
};

/** ESP-IDF's names for partition types (`gen_esp32part.py` `TYPES`). */
const TYPE_NAMES: Readonly<Record<number, string>> = {
  0x00: "app",
  0x01: "data",
  0x02: "bootloader",
  0x03: "partition_table",
};

/** ESP-IDF's subtype names per type (`gen_esp32part.py` `SUBTYPES`). */
const SUBTYPE_NAMES: Readonly<
  Record<number, Readonly<Record<number, string>>>
> = {
  0x00: {
    0x00: "factory",
    0x20: "test",
    ...Object.fromEntries(
      Array.from({ length: 16 }, (_, slot) => [
        0x10 + slot,
        `ota_${String(slot)}`,
      ]),
    ),
    0x30: "tee_0",
    0x31: "tee_1",
  },
  0x01: {
    0x00: "ota",
    0x01: "phy",
    0x02: "nvs",
    0x03: "coredump",
    0x04: "nvs_keys",
    0x05: "efuse",
    0x06: "undefined",
    0x80: "esphttpd",
    0x81: "fat",
    0x82: "spiffs",
    0x83: "littlefs",
    0x90: "tee_ota",
  },
  0x02: { 0x00: "primary", 0x01: "ota", 0x02: "recovery" },
  0x03: { 0x00: "primary", 0x01: "ota" },
};

export const espPartitionTypeName = (type: number): string | null =>
  TYPE_NAMES[type] ?? null;

export const espPartitionSubtypeName = (
  type: number,
  subtype: number,
): string | null => SUBTYPE_NAMES[type]?.[subtype] ?? null;

const APP_TYPE = 0x00;
const OTA_DATA_SUBTYPE = 0x00;
const DATA_TYPE = 0x01;
const OTA_APP_SUBTYPE_FLAG = 0x10;
const OTA_APP_SUBTYPE_MASK = 0x0f;

/** The OTA slot of an app partition (`ota_0` to `ota_15`), if it has one. */
export const espOtaAppSlot = (part: EspPartition): number | null =>
  part.type === APP_TYPE &&
  (part.subtype & ~OTA_APP_SUBTYPE_MASK) === OTA_APP_SUBTYPE_FLAG
    ? part.subtype & OTA_APP_SUBTYPE_MASK
    : null;

export const isEspFactoryApp = (part: EspPartition): boolean =>
  part.type === APP_TYPE && part.subtype === 0x00;

export const isEspOtaData = (part: EspPartition): boolean =>
  part.type === DATA_TYPE && part.subtype === OTA_DATA_SUBTYPE;

export const isEspAppPartition = (part: EspPartition): boolean =>
  part.type === APP_TYPE;
