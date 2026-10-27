import { describe, expect, it } from "vitest";

import {
  locateEspFlashLayout,
  type EspFlashSelection,
} from "./espFlashLocation.js";
import {
  TWO_OTA_PARTITIONS,
  flashImage,
  partitionTable,
} from "./espFlash.fixture.js";
import { ESP32C3_BOOTLOADER_SEGMENTS, espImage } from "./espImage.fixture.js";

const c3Bootloader = espImage({ segments: ESP32C3_BOOTLOADER_SEGMENTS });
const esp32Bootloader = espImage({
  segments: ESP32C3_BOOTLOADER_SEGMENTS,
  chipId: 0x0000,
});

const locate = (
  bytes: Uint8Array,
  selection: EspFlashSelection = {},
  explicit = false,
) =>
  locateEspFlashLayout(
    bytes.length,
    async (position, length) =>
      bytes.subarray(Math.max(0, position), Math.max(0, position) + length),
    selection,
    { explicit },
  );

const dump = (
  tableAt: number,
  {
    bootloader = c3Bootloader,
    bootloaderAt = 0,
    md5 = "valid",
  }: {
    readonly bootloader?: Uint8Array;
    readonly bootloaderAt?: number;
    readonly md5?: "valid" | "corrupt" | "absent";
  } = {},
) =>
  flashImage(0x2_0000, [
    { at: bootloaderAt, bytes: bootloader },
    { at: tableAt, bytes: partitionTable(TWO_OTA_PARTITIONS, { md5 }) },
  ]);

describe("ESP flash layout location", () => {
  it("finds the bootloader and the table at their default offsets", async () => {
    const located = await locate(dump(0x8000));
    expect(located.ok && located.value).toMatchObject({
      origin: { value: 0, source: "default" },
      bootloader: { flashAddress: 0, chip: { target: "esp32c3" } },
      tableAddress: 0x8000,
      tableMethod: "default",
      table: { md5: { status: "valid" } },
      limitations: [],
    });
  });

  it("scans for a relocated table only when its MD5 verifies", async () => {
    const located = await locate(dump(0xa000));
    expect(located.ok && located.value).toMatchObject({
      tableAddress: 0xa000,
      tableMethod: "scan",
    });
    expect(await locate(dump(0xa000, { md5: "absent" }))).toEqual({
      ok: false,
      error:
        "no partition table at 0x8000 or in any 0x1000-aligned flash sector with a verified MD5; flash encryption is one cause",
    });
  });

  it("uses the caller's table offset and does not scan", async () => {
    const located = await locate(dump(0xa000), {
      partitionTableOffset: 0xa000,
    });
    expect(located.ok && located.value).toMatchObject({
      tableAddress: 0xa000,
      tableMethod: "caller",
    });
    expect(
      await locate(dump(0xa000), { partitionTableOffset: 0x9000 }),
    ).toEqual({
      ok: false,
      error:
        "no partition table at the given offset 0x9000: the first entry is empty",
    });
  });

  it("reads a dump that starts after flash address 0 at the caller's origin", async () => {
    // An ESP32 dump read from 0x1000: its bootloader is the file's first byte.
    const partial = dump(0x8000, {
      bootloader: esp32Bootloader,
      bootloaderAt: 0x1000,
    }).subarray(0x1000);
    const located = await locate(partial, { flashOffset: 0x1000 });
    expect(located.ok && located.value).toMatchObject({
      origin: { value: 0x1000, source: "caller" },
      bootloader: {
        flashAddress: 0x1000,
        fileOffset: 0,
        chip: { target: "esp32" },
      },
      tableAddress: 0x8000,
      tableMethod: "default",
    });
    // Without the origin, the bootloader's chip says the dump is misplaced, so
    // a scan would misplace every partition by 0x1000; none is attempted.
    const misplaced = await locate(partial);
    expect(misplaced.ok).toBe(false);
    expect(!misplaced.ok && misplaced.error).toContain("Pass flash_offset");
  });

  it("does not scan arbitrary files without a bootloader unless the format was selected", async () => {
    const bare = flashImage(0x2_0000, [
      { at: 0xa000, bytes: partitionTable(TWO_OTA_PARTITIONS) },
    ]);
    expect(await locate(bare)).toEqual({
      ok: false,
      error: "no partition table at 0x8000 and no bootloader at a ROM offset",
    });
    const explicit = await locate(bare, {}, true);
    expect(explicit.ok && explicit.value).toMatchObject({
      bootloader: undefined,
      tableAddress: 0xa000,
      tableMethod: "scan",
    });
  });

  it("rejects a table offset outside the dump", async () => {
    expect(
      await locate(dump(0x8000), { partitionTableOffset: 0x10_0000 }),
    ).toEqual({
      ok: false,
      error:
        "the partition table offset 0x100000 is outside the dump, which holds flash 0x0-0x20000",
    });
  });
});
