import { offsetText } from "./espImageStructures.js";
import type { EspBootloaderLocation } from "./espFlashBootloader.js";
import {
  ESP_PARTITION_TABLE_SECTOR_BYTES,
  espPartitionSubtypeName,
  espPartitionTypeName,
  isEspOtaData,
  type EspPartition,
  type EspPartitionTable,
} from "./espPartitionTable.js";
import {
  ESP_OTA_DATA_SECTOR_BYTES,
  decodeEspOtaRecord,
  selectEspOtaSlot,
  type EspOtaRecord,
  type EspOtaSelection,
} from "./espOtaData.js";

/** Where the file's first byte sits in flash, and who said so. */
export interface EspFlashOrigin {
  readonly value: number;
  readonly source: "default" | "caller";
}

export type EspPartitionTableMethod = "default" | "caller" | "scan";

/** One described byte range of the dump, in flash and in the file. */
export interface EspFlashRegion {
  readonly path: string;
  readonly role: "bootloader" | "partition-table" | "partition";
  readonly flashAddress: number;
  /** Length the layout gives the region. */
  readonly length: number;
  readonly fileOffset: number;
  /** Bytes of the region the file holds, from `fileOffset`. */
  readonly available: number;
  readonly partition: EspPartition | undefined;
}

export interface EspFlashPlanInput {
  readonly fileSize: number;
  readonly origin: EspFlashOrigin;
  readonly bootloader: EspBootloaderLocation | undefined;
  readonly tableAddress: number;
  readonly tableMethod: EspPartitionTableMethod;
  readonly table: EspPartitionTable;
}

/** Regions to inventory and the byte ranges the adapter must still read. */
export interface EspFlashPlan {
  readonly input: EspFlashPlanInput;
  readonly regions: readonly EspFlashRegion[];
  /** File ranges no region describes; erased flash there is described. */
  readonly gaps: readonly {
    readonly offset: number;
    readonly length: number;
  }[];
  /** File offsets of the two otadata records, when the file holds them. */
  readonly otadata:
    | {
        readonly partition: EspPartition;
        readonly records: readonly [number, number];
      }
    | undefined;
  readonly limitations: readonly string[];
}

const SAFE_LABEL = /^(?=.*[A-Za-z_])[A-Za-z0-9_][A-Za-z0-9._-]{0,15}$/u;

/**
 * Partition paths use the label when it is a safe, unique path segment
 * with a letter or underscore, else the table index, which then cannot
 * collide with a label.
 */
const partitionPaths = (
  partitions: readonly EspPartition[],
): ReadonlyMap<number, string> => {
  const counts = new Map<string, number>();
  for (const { label } of partitions)
    if (label !== null) counts.set(label, (counts.get(label) ?? 0) + 1);
  return new Map(
    partitions.map((part) => {
      const label = part.label;
      const named =
        label !== null && SAFE_LABEL.test(label) && counts.get(label) === 1;
      return [
        part.index,
        `partitions/${named ? label : String(part.index)}.bin`,
      ];
    }),
  );
};

const region = (
  input: EspFlashPlanInput,
  fields: Omit<EspFlashRegion, "fileOffset" | "available">,
): EspFlashRegion => {
  const fileOffset = fields.flashAddress - input.origin.value;
  const start = Math.max(0, fileOffset);
  const end = Math.min(input.fileSize, fileOffset + fields.length);
  return { ...fields, fileOffset, available: Math.max(0, end - start) };
};

const rangeText = (address: number, length: number): string =>
  `${offsetText(address)}-${offsetText(address + length)}`;

/** Lay the bootloader, table and partitions over the dump. */
export const planEspFlashLayout = (input: EspFlashPlanInput): EspFlashPlan => {
  const limitations: string[] = [...input.table.limitations];
  const regions: EspFlashRegion[] = [];
  const tableEnd = input.tableAddress + ESP_PARTITION_TABLE_SECTOR_BYTES;
  const { bootloader } = input;
  if (bootloader !== undefined) {
    if (bootloader.flashAddress < input.tableAddress)
      regions.push(
        region(input, {
          path: "bootloader.bin",
          role: "bootloader",
          // ESP_BOOTLOADER_SIZE: from the bootloader to the partition table.
          flashAddress: bootloader.flashAddress,
          length: input.tableAddress - bootloader.flashAddress,
          partition: undefined,
        }),
      );
    else
      limitations.push(
        `The partition table at ${offsetText(input.tableAddress)} does not follow the bootloader at ${offsetText(bootloader.flashAddress)}; the bootloader region is not described.`,
      );
  }
  regions.push(
    region(input, {
      path: "partition-table.bin",
      role: "partition-table",
      flashAddress: input.tableAddress,
      length: ESP_PARTITION_TABLE_SECTOR_BYTES,
      partition: undefined,
    }),
  );
  const paths = partitionPaths(input.table.partitions);
  for (const part of input.table.partitions) {
    const placed = region(input, {
      path: paths.get(part.index) ?? `partitions/${String(part.index)}.bin`,
      role: "partition",
      flashAddress: part.offset,
      length: part.size,
      partition: part,
    });
    const name = part.label ?? `#${String(part.index)}`;
    if (part.offset < tableEnd)
      limitations.push(
        `Partition ${name} at ${offsetText(part.offset)} starts before the end of the partition table at ${offsetText(tableEnd)}; gen_esp32part.py rejects such a table.`,
      );
    if (placed.fileOffset < 0)
      limitations.push(
        `Partition ${name} at ${offsetText(part.offset)} begins before the dump's first byte at flash ${offsetText(input.origin.value)}; it is not read.`,
      );
    else if (placed.available === 0)
      limitations.push(
        `Partition ${name} at ${rangeText(part.offset, part.size)} lies outside the dump, which ends at flash ${offsetText(input.origin.value + input.fileSize)}.`,
      );
    else if (placed.available < part.size)
      limitations.push(
        `Partition ${name} at ${rangeText(part.offset, part.size)} is truncated: the dump holds ${String(placed.available)} of its ${String(part.size)} bytes.`,
      );
    if (placed.fileOffset >= 0 && placed.available > 0) regions.push(placed);
  }
  limitations.push(...overlaps(regions));
  const otadataPartition = input.table.partitions.find(isEspOtaData);
  const otadataStart =
    otadataPartition === undefined
      ? undefined
      : otadataPartition.offset - input.origin.value;
  const otadata =
    otadataPartition === undefined || otadataStart === undefined
      ? undefined
      : otadataStart >= 0 &&
          otadataStart + ESP_OTA_DATA_SECTOR_BYTES + 32 <= input.fileSize
        ? {
            partition: otadataPartition,
            records: [
              otadataStart,
              otadataStart + ESP_OTA_DATA_SECTOR_BYTES,
            ] as const,
          }
        : undefined;
  if (otadataPartition !== undefined && otadata === undefined)
    limitations.push(
      `The dump does not hold both otadata records of partition ${otadataPartition.label ?? `#${String(otadataPartition.index)}`}; the OTA selection is unknown.`,
    );
  return {
    input,
    regions,
    gaps: gapsBetween(regions, input.fileSize),
    otadata,
    limitations,
  };
};

/** Regions that share bytes, which gen_esp32part.py rejects for partitions. */
const overlaps = (regions: readonly EspFlashRegion[]): string[] => {
  const ordered = [...regions].sort(
    (left, right) => left.flashAddress - right.flashAddress,
  );
  const found: string[] = [];
  for (let index = 1; index < ordered.length; index += 1) {
    const previous = ordered[index - 1];
    const current = ordered[index];
    if (
      previous !== undefined &&
      current !== undefined &&
      current.flashAddress < previous.flashAddress + previous.length
    )
      found.push(
        `${current.path} at ${offsetText(current.flashAddress)} overlaps ${previous.path}, which ends at ${offsetText(previous.flashAddress + previous.length)}.`,
      );
  }
  return found;
};

/** File ranges outside every region, in order. */
const gapsBetween = (
  regions: readonly EspFlashRegion[],
  fileSize: number,
): { offset: number; length: number }[] => {
  const covered = regions
    .map(({ fileOffset, available }) => ({
      start: Math.max(0, fileOffset),
      end: Math.max(0, fileOffset) + available,
    }))
    .filter(({ end, start }) => end > start)
    .sort((left, right) => left.start - right.start);
  const gaps: { offset: number; length: number }[] = [];
  let cursor = 0;
  for (const { start, end } of covered) {
    if (start > cursor) gaps.push({ offset: cursor, length: start - cursor });
    cursor = Math.max(cursor, end);
  }
  if (fileSize > cursor)
    gaps.push({ offset: cursor, length: fileSize - cursor });
  return gaps;
};

export interface EspFlashOtaFacts {
  readonly partition_index: number;
  readonly records: readonly EspOtaRecord[];
  /** Derived from the records; see its assumptions. */
  readonly selected: EspOtaSelection;
  /** The bootloader's rollback and fallback decide it at boot. */
  readonly running_partition: "unknown";
}

/** Facts the adapter read for the plan: the otadata records and the gaps. */
export interface EspFlashReads {
  readonly otadataRecords: readonly [Uint8Array, Uint8Array] | undefined;
  /** The first non-erased file offset in each gap, in plan order. */
  readonly gapFirstUnerased: readonly (number | undefined)[];
}

export interface EspFlashLayoutFacts {
  readonly otadata: EspFlashOtaFacts | null;
  readonly undescribed: readonly { offset: number; length: number }[];
  readonly coverage: "complete" | "unknown";
  readonly limitations: readonly string[];
}

/** Complete the plan with the bytes the adapter read. */
export const finishEspFlashLayout = (
  plan: EspFlashPlan,
  reads: EspFlashReads,
): EspFlashLayoutFacts => {
  const limitations = [...plan.limitations];
  const undescribed: { offset: number; length: number }[] = [];
  plan.gaps.forEach((gap, index) => {
    const first = reads.gapFirstUnerased[index];
    if (first !== undefined)
      undescribed.push({
        offset: first,
        length: gap.offset + gap.length - first,
      });
  });
  const total = undescribed.reduce((sum, { length }) => sum + length, 0);
  if (undescribed.length > 0)
    limitations.push(
      `${String(total)} bytes of the dump, in ${String(undescribed.length)} range(s), lie outside the bootloader region, the partition table and every partition and are not erased flash.`,
    );
  const otadata =
    plan.otadata === undefined || reads.otadataRecords === undefined
      ? null
      : otaFacts(plan, reads.otadataRecords);
  const incomplete = plan.input.table.partitions.some((part) => {
    const region = plan.regions.find((item) => item.partition === part);
    return region === undefined || region.available < part.size;
  });
  return {
    otadata,
    undescribed,
    coverage:
      undescribed.length > 0 ||
      incomplete ||
      plan.input.bootloader === undefined
        ? "unknown"
        : "complete",
    limitations,
  };
};

const otaFacts = (
  plan: EspFlashPlan,
  [first, second]: readonly [Uint8Array, Uint8Array],
): EspFlashOtaFacts | null => {
  if (plan.otadata === undefined) return null;
  const records = [decodeEspOtaRecord(first, 0), decodeEspOtaRecord(second, 1)];
  return {
    partition_index: plan.otadata.partition.index,
    records,
    selected: selectEspOtaSlot(records, plan.input.table.partitions),
    running_partition: "unknown",
  };
};

/** Flat entry metadata for one partition, as the table declares it. */
export const espFlashPartitionFacts = (part: EspPartition) => ({
  kind: "esp-flash-partition" as const,
  index: part.index,
  label: part.label,
  type: part.type,
  subtype: part.subtype,
  type_name: espPartitionTypeName(part.type),
  subtype_name: espPartitionSubtypeName(part.type, part.subtype),
  flash_address: part.offset,
  size: part.size,
  encrypted: part.encrypted,
  readonly: part.readonly,
  unknown_flags: part.unknownFlags,
});
