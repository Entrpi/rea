import { crc32 } from "node:zlib";

import { hex, u32 } from "./espImageStructures.js";
import {
  espOtaAppSlot,
  isEspFactoryApp,
  type EspPartition,
} from "./espPartitionTable.js";

/*
 * OTA data, from ESP-IDF v6.1 `esp_flash_partitions.h`
 * (`esp_ota_select_entry_t`, `esp_ota_img_states_t`),
 * `bootloader_common_loader.c` and `bootloader_utility.c`
 * (`bootloader_utility_get_selected_boot_partition`), and `otatool.py`.
 */
/** The otadata partition holds one record at the start of each of two sectors. */
export const ESP_OTA_DATA_SECTOR_BYTES = 0x1000;
export const ESP_OTA_SELECT_ENTRY_BYTES = 32;
const UNSET = 0xffff_ffff;

export type EspOtaStateName =
  | "new"
  | "pending-verify"
  | "valid"
  | "invalid"
  | "aborted"
  | "undefined";

const STATE_NAMES: Readonly<Record<number, EspOtaStateName>> = {
  0x0: "new",
  0x1: "pending-verify",
  0x2: "valid",
  0x3: "invalid",
  0x4: "aborted",
  [UNSET]: "undefined",
};

/** One `esp_ota_select_entry_t`, observed as written. */
export interface EspOtaRecord {
  readonly index: 0 | 1;
  readonly ota_seq: number;
  readonly seq_label: string;
  readonly ota_state: number;
  readonly state_name: EspOtaStateName | null;
  readonly crc: number;
  /** CRC-32 of `ota_seq`, seeded with `0xFFFFFFFF`, as the bootloader computes it. */
  readonly crc_matches: boolean;
  /** `bootloader_common_ota_select_valid`: set sequence, usable state, matching CRC. */
  readonly valid: boolean;
}

export const decodeEspOtaRecord = (
  bytes: Uint8Array,
  index: 0 | 1,
): EspOtaRecord => {
  const sequence = bytes.subarray(0, 4);
  const otaSeq = u32(bytes, 0);
  const state = u32(bytes, 24);
  const crc = u32(bytes, 28);
  const crcMatches = crc32(sequence, UNSET) >>> 0 === crc;
  return {
    index,
    ota_seq: otaSeq,
    seq_label: hex(bytes.subarray(4, 24)),
    ota_state: state,
    state_name: STATE_NAMES[state] ?? null,
    crc,
    crc_matches: crcMatches,
    valid: otaSeq !== UNSET && state !== 0x3 && state !== 0x4 && crcMatches,
  };
};

export const ESP_OTA_SELECTION_ASSUMPTIONS = [
  "Records are used as written: the bootloader may first mark a pending-verify record aborted when app rollback is enabled.",
  "Anti-rollback, which compares the app's secure_version with eFuse, is not applied.",
  "The selected app is not checked for a loadable image; the bootloader falls back to other partitions when it fails to load.",
] as const;

export interface EspOtaSelection {
  /** The record the bootloader reads as active: the higher valid `ota_seq`. */
  readonly active_record: 0 | 1 | null;
  /** `(ota_seq - 1) % ota_app_count`, the bootloader's slot arithmetic. */
  readonly slot: number | null;
  /** The table index of the app partition for that slot or the fallback. */
  readonly partition_index: number | null;
  readonly basis: "otadata" | "factory-fallback" | "ota_0-fallback" | "none";
  readonly assumptions: readonly string[];
}

/** `bootloader_common_ota_select_invalid`, which does not check the CRC. */
const unusable = ({ ota_seq, ota_state }: EspOtaRecord): boolean =>
  ota_seq === UNSET || ota_state === 0x3 || ota_state === 0x4;

/**
 * Derive the app partition the bootloader would select from these records,
 * as `bootloader_utility_get_selected_boot_partition` does without app
 * rollback or anti-rollback:
 * - both records unusable, or no OTA app: the factory app, else `ota_0`;
 * - otherwise the valid record with the higher `ota_seq` (record 0 on a
 *   tie), whose slot is `(ota_seq - 1) % ota_app_count`;
 * - no valid record (a CRC mismatch): the factory app, else none, because
 *   the bootloader then tries every partition.
 */
export const selectEspOtaSlot = (
  records: readonly EspOtaRecord[],
  partitions: readonly EspPartition[],
): EspOtaSelection => {
  // The bootloader counts every OTA app but indexes them by subtype, and a
  // later entry with the same subtype replaces an earlier one.
  let appCount = 0;
  const bySlot = new Map<number, EspPartition>();
  for (const part of partitions) {
    const slot = espOtaAppSlot(part);
    if (slot === null) continue;
    appCount += 1;
    bySlot.set(slot, part);
  }
  const factory = partitions.find(isEspFactoryApp);
  const assumptions = [...ESP_OTA_SELECTION_ASSUMPTIONS];
  const none = {
    active_record: null,
    slot: null,
    partition_index: null,
    basis: "none",
    assumptions,
  } as const;
  const factoryFallback =
    factory === undefined
      ? undefined
      : ({
          ...none,
          partition_index: factory.index,
          basis: "factory-fallback",
        } as const);
  if (records.every(unusable) || appCount === 0) {
    if (factoryFallback !== undefined) return factoryFallback;
    const first = bySlot.get(0);
    return first === undefined
      ? none
      : {
          ...none,
          slot: 0,
          partition_index: first.index,
          basis: "ota_0-fallback",
        };
  }
  const valid = records.filter(({ valid }) => valid);
  const [first, second] = valid;
  const active =
    first !== undefined &&
    second !== undefined &&
    second.ota_seq > first.ota_seq
      ? second
      : first;
  if (active === undefined) return factoryFallback ?? none;
  const slot = ((active.ota_seq - 1) >>> 0) % appCount;
  return {
    active_record: active.index,
    slot,
    // A gap in the OTA subtypes selects a slot with no partition.
    partition_index: bySlot.get(slot)?.index ?? null,
    basis: "otadata",
    assumptions,
  };
};
