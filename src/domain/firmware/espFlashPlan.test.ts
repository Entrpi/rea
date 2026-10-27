import { describe, expect, it } from "vitest";

import { espChipForId } from "./espChips.js";
import {
  espFlashPartitionFacts,
  finishEspFlashLayout,
  planEspFlashLayout,
  type EspFlashPlanInput,
} from "./espFlashLayout.js";
import {
  decodeEspPartitionTable,
  type EspPartitionTable,
} from "./espPartitionTable.js";
import {
  TWO_OTA_PARTITIONS,
  otaRecord,
  partitionTable,
  type EspPartitionFixture,
} from "./espFlash.fixture.js";

const table = (parts: readonly EspPartitionFixture[]): EspPartitionTable => {
  const decoded = decodeEspPartitionTable(partitionTable(parts));
  if (!decoded.ok) throw new Error(decoded.error);
  return decoded.value;
};

const c3 = espChipForId(0x0005)!;

const input = (fields: Partial<EspFlashPlanInput> = {}): EspFlashPlanInput => ({
  fileSize: 0x4_0000,
  origin: { value: 0, source: "default" },
  bootloader: { flashAddress: 0, fileOffset: 0, chip: c3 },
  tableAddress: 0x8000,
  tableMethod: "default",
  table: table(TWO_OTA_PARTITIONS),
  ...fields,
});

const erasedGaps = (count: number) =>
  Array.from({ length: count }, () => undefined);

describe("ESP flash layout plans", () => {
  it("describes the bootloader region, the table sector and every partition", () => {
    const plan = planEspFlashLayout(input());
    expect(
      plan.regions.map(({ path, flashAddress, length, available }) => [
        path,
        flashAddress,
        length,
        available,
      ]),
    ).toEqual([
      ["bootloader.bin", 0, 0x8000, 0x8000],
      ["partition-table.bin", 0x8000, 0x1000, 0x1000],
      ["partitions/nvs.bin", 0x9000, 0x4000, 0x4000],
      ["partitions/otadata.bin", 0xd000, 0x2000, 0x2000],
      ["partitions/phy_init.bin", 0xf000, 0x1000, 0x1000],
      ["partitions/factory.bin", 0x1_0000, 0x1_0000, 0x1_0000],
      ["partitions/ota_0.bin", 0x2_0000, 0x1_0000, 0x1_0000],
      ["partitions/ota_1.bin", 0x3_0000, 0x1_0000, 0x1_0000],
    ]);
    expect(plan.gaps).toEqual([]);
    expect(plan.otadata?.records).toEqual([0xd000, 0xe000]);
    expect(plan.limitations).toEqual([]);
  });

  it("falls back to the index for unsafe or repeated labels", () => {
    const parts: EspPartitionFixture[] = [
      { label: "../x", type: 1, subtype: 2, offset: 0x9000, size: 0x1000 },
      { label: "dup", type: 1, subtype: 2, offset: 0xa000, size: 0x1000 },
      { label: "dup", type: 1, subtype: 2, offset: 0xb000, size: 0x1000 },
      { label: "7", type: 1, subtype: 2, offset: 0xc000, size: 0x1000 },
    ];
    expect(
      planEspFlashLayout(input({ table: table(parts) }))
        .regions.map(({ path }) => path)
        .slice(2),
    ).toEqual([
      "partitions/0.bin",
      "partitions/1.bin",
      "partitions/2.bin",
      "partitions/3.bin",
    ]);
  });

  it("keeps a usable partition beside truncated, missing and early ones", () => {
    const plan = planEspFlashLayout(
      input({
        fileSize: 0x3_8000,
        origin: { value: 0x1000, source: "caller" },
        bootloader: undefined,
        table: table([
          { label: "early", type: 1, subtype: 2, offset: 0x0, size: 0x1000 },
          {
            label: "app",
            type: 0,
            subtype: 0,
            offset: 0x1_0000,
            size: 0x1_0000,
          },
          {
            label: "cut",
            type: 0,
            subtype: 0x10,
            offset: 0x3_0000,
            size: 0x1_0000,
          },
          {
            label: "gone",
            type: 1,
            subtype: 0x82,
            offset: 0x10_0000,
            size: 0x1000,
          },
        ]),
      }),
    );
    expect(
      plan.regions.map(({ path, fileOffset, available }) => [
        path,
        fileOffset,
        available,
      ]),
    ).toEqual([
      ["partition-table.bin", 0x7000, 0x1000],
      ["partitions/app.bin", 0xf000, 0x1_0000],
      ["partitions/cut.bin", 0x2_f000, 0x9000],
    ]);
    expect(plan.limitations).toEqual([
      "Partition early at 0x0 starts before the end of the partition table at 0x9000; gen_esp32part.py rejects such a table.",
      "Partition early at 0x0 begins before the dump's first byte at flash 0x1000; it is not read.",
      "Partition cut at 0x30000-0x40000 is truncated: the dump holds 36864 of its 65536 bytes.",
      "Partition gone at 0x100000-0x101000 lies outside the dump, which ends at flash 0x39000.",
    ]);
    const facts = finishEspFlashLayout(plan, {
      otadataRecords: undefined,
      gapFirstUnerased: erasedGaps(plan.gaps.length),
    });
    expect(facts.coverage).toBe("unknown");
  });

  it("reports overlapping regions", () => {
    const plan = planEspFlashLayout(
      input({
        table: table([
          { label: "a", type: 1, subtype: 2, offset: 0x9000, size: 0x2000 },
          { label: "b", type: 1, subtype: 2, offset: 0xa000, size: 0x1000 },
        ]),
      }),
    );
    expect(plan.limitations).toEqual([
      "partitions/b.bin at 0xa000 overlaps partitions/a.bin, which ends at 0xb000.",
    ]);
  });
});

describe("ESP flash layout facts", () => {
  it("describes erased gaps and reports the rest as undescribed", () => {
    const plan = planEspFlashLayout(
      input({
        table: table(TWO_OTA_PARTITIONS.slice(0, 3)),
        fileSize: 0x2_0000,
      }),
    );
    expect(plan.gaps).toEqual([{ offset: 0x1_0000, length: 0x1_0000 }]);
    const erased = finishEspFlashLayout(plan, {
      otadataRecords: undefined,
      gapFirstUnerased: [undefined],
    });
    expect(erased).toMatchObject({ coverage: "complete", undescribed: [] });
    const written = finishEspFlashLayout(plan, {
      otadataRecords: undefined,
      gapFirstUnerased: [0x1_8000],
    });
    expect(written.undescribed).toEqual([{ offset: 0x1_8000, length: 0x8000 }]);
    expect(written.coverage).toBe("unknown");
    expect(written.limitations.at(-1)).toBe(
      "32768 bytes of the dump, in 1 range(s), lie outside the bootloader region, the partition table and every partition and are not erased flash.",
    );
  });

  it("derives the selected app from the otadata records and leaves the running one unknown", () => {
    const plan = planEspFlashLayout(input());
    const facts = finishEspFlashLayout(plan, {
      otadataRecords: [otaRecord({ seq: 2 }), Buffer.alloc(32, 0xff)],
      gapFirstUnerased: [],
    });
    expect(facts.otadata).toMatchObject({
      partition_index: 1,
      records: [{ ota_seq: 2, valid: true }, { valid: false }],
      selected: {
        active_record: 0,
        slot: 1,
        partition_index: 5,
        basis: "otadata",
      },
      running_partition: "unknown",
    });
    expect(facts.coverage).toBe("complete");
  });

  it("projects a partition's declaration with ESP-IDF names", () => {
    const [nvs] = table(TWO_OTA_PARTITIONS).partitions;
    expect(espFlashPartitionFacts(nvs!)).toEqual({
      kind: "esp-flash-partition",
      index: 0,
      label: "nvs",
      type: 1,
      subtype: 2,
      type_name: "data",
      subtype_name: "nvs",
      flash_address: 0x9000,
      size: 0x4000,
      encrypted: false,
      readonly: false,
      unknown_flags: 0,
    });
  });
});
