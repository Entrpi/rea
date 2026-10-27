import { err, ok, type Result } from "../result.js";
import {
  ESP_BOOTLOADER_PROBE_BYTES,
  espBootloaderProbeOffsets,
  locateEspBootloader,
  type EspBootloaderLocation,
} from "./espFlashBootloader.js";
import type {
  EspFlashOrigin,
  EspPartitionTableMethod,
} from "./espFlashLayout.js";
import { offsetText } from "./espImageStructures.js";
import {
  ESP_PARTITION_TABLE_DEFAULT_OFFSET,
  ESP_PARTITION_TABLE_MAX_BYTES,
  ESP_PARTITION_TABLE_SECTOR_BYTES,
  decodeEspPartitionTable,
  type EspPartitionTable,
} from "./espPartitionTable.js";

/** Caller inputs that select how a dump is read; omitted means the default. */
export interface EspFlashSelection {
  /** Flash address of the dump's first byte. */
  readonly flashOffset?: number | undefined;
  /** Flash address of the partition table; it disables the scan. */
  readonly partitionTableOffset?: number | undefined;
}

/** Where the layout sits in the dump, found once and shared by its readers. */
export interface EspFlashLocation {
  readonly origin: EspFlashOrigin;
  readonly bootloader: EspBootloaderLocation | undefined;
  readonly tableAddress: number;
  readonly tableMethod: EspPartitionTableMethod;
  readonly table: EspPartitionTable;
  readonly limitations: readonly string[];
}

/** Read up to `length` bytes at a file offset; fewer means end of file. */
export type EspFlashRead = (
  position: number,
  length: number,
) => Promise<Uint8Array>;

const SCAN_CHUNK_BYTES = 0x1_0000;
const MAGIC_LOW = 0xaa;
const MAGIC_HIGH = 0x50;

const tableAt = async (
  read: EspFlashRead,
  fileOffset: number,
): Promise<Result<EspPartitionTable, string>> =>
  decodeEspPartitionTable(
    await read(fileOffset, ESP_PARTITION_TABLE_MAX_BYTES),
  );

/**
 * The first sector-aligned table whose MD5 verifies; requiring the MD5
 * keeps arbitrary bytes that begin with the magic from passing.
 */
const scanForTable = async (
  read: EspFlashRead,
  fileSize: number,
  origin: number,
  signal?: AbortSignal,
): Promise<{ address: number; table: EspPartitionTable } | undefined> => {
  const skew =
    (ESP_PARTITION_TABLE_SECTOR_BYTES -
      (origin % ESP_PARTITION_TABLE_SECTOR_BYTES)) %
    ESP_PARTITION_TABLE_SECTOR_BYTES;
  for (let chunk = 0; chunk < fileSize; chunk += SCAN_CHUNK_BYTES) {
    signal?.throwIfAborted();
    // One extra byte lets a sector head at the chunk's last byte be checked.
    const bytes = await read(chunk, SCAN_CHUNK_BYTES + 1);
    const first =
      chunk +
      ((skew -
        (chunk % ESP_PARTITION_TABLE_SECTOR_BYTES) +
        ESP_PARTITION_TABLE_SECTOR_BYTES) %
        ESP_PARTITION_TABLE_SECTOR_BYTES);
    for (
      let position = first;
      position < chunk + SCAN_CHUNK_BYTES && position < fileSize;
      position += ESP_PARTITION_TABLE_SECTOR_BYTES
    ) {
      const at = position - chunk;
      if (bytes[at] !== MAGIC_LOW || bytes[at + 1] !== MAGIC_HIGH) continue;
      const decoded = await tableAt(read, position);
      if (decoded.ok && decoded.value.md5.status === "valid")
        return { address: origin + position, table: decoded.value };
    }
  }
  return undefined;
};

/**
 * Locate the bootloader and partition table: the caller's table offset
 * when given, else the default `0x8000`, else a scan of 0x1000-aligned
 * flash sectors for an MD5-verified table (a derived location). The scan
 * runs only when a bootloader sits at its chip's ROM offset or the caller
 * selected this format, and never when a bootloader at another chip's ROM
 * offset says the dump's origin is wrong.
 */
export const locateEspFlashLayout = async (
  fileSize: number,
  read: EspFlashRead,
  selection: EspFlashSelection,
  {
    explicit,
    signal,
  }: { readonly explicit: boolean; readonly signal?: AbortSignal },
): Promise<Result<EspFlashLocation, string>> => {
  const origin: EspFlashOrigin =
    selection.flashOffset === undefined
      ? { value: 0, source: "default" }
      : { value: selection.flashOffset, source: "caller" };
  const probes = await Promise.all(
    espBootloaderProbeOffsets(origin.value, fileSize).map(
      async ({ flashAddress, fileOffset }) => ({
        flashAddress,
        fileOffset,
        prefix: await read(fileOffset, ESP_BOOTLOADER_PROBE_BYTES),
        available: fileSize - fileOffset,
      }),
    ),
  );
  const bootloader = locateEspBootloader(probes);
  const located = (
    tableAddress: number,
    tableMethod: EspPartitionTableMethod,
    table: EspPartitionTable,
  ): Result<EspFlashLocation, string> =>
    ok({
      origin,
      bootloader: bootloader.location,
      tableAddress,
      tableMethod,
      table,
      limitations: bootloader.limitations,
    });
  const fileOffsetOf = (address: number): number => address - origin.value;
  if (selection.partitionTableOffset !== undefined) {
    const address = selection.partitionTableOffset;
    if (fileOffsetOf(address) < 0 || fileOffsetOf(address) >= fileSize)
      return err(
        `the partition table offset ${offsetText(address)} is outside the dump, which holds flash ${offsetText(origin.value)}-${offsetText(origin.value + fileSize)}`,
      );
    const decoded = await tableAt(read, fileOffsetOf(address));
    return decoded.ok
      ? located(address, "caller", decoded.value)
      : err(
          `no partition table at the given offset ${offsetText(address)}: ${decoded.error}`,
        );
  }
  const defaultOffset = fileOffsetOf(ESP_PARTITION_TABLE_DEFAULT_OFFSET);
  if (defaultOffset >= 0 && defaultOffset < fileSize) {
    const decoded = await tableAt(read, defaultOffset);
    if (decoded.ok)
      return located(
        ESP_PARTITION_TABLE_DEFAULT_OFFSET,
        "default",
        decoded.value,
      );
  }
  const misplaced =
    bootloader.location === undefined && bootloader.limitations.length > 0;
  if (misplaced && selection.flashOffset === undefined)
    return err(
      `no partition table at ${offsetText(ESP_PARTITION_TABLE_DEFAULT_OFFSET)}, and ${bootloader.limitations.join(" ")} Pass flash_offset to read the dump from another flash address`,
    );
  if (bootloader.location === undefined && !explicit)
    return err(
      `no partition table at ${offsetText(ESP_PARTITION_TABLE_DEFAULT_OFFSET)} and no bootloader at a ROM offset`,
    );
  const scanned = await scanForTable(read, fileSize, origin.value, signal);
  return scanned === undefined
    ? err(
        `no partition table at ${offsetText(ESP_PARTITION_TABLE_DEFAULT_OFFSET)} or in any 0x1000-aligned flash sector with a verified MD5; flash encryption is one cause`,
      )
    : located(scanned.address, "scan", scanned.table);
};
