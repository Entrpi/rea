# ESP flash images

REA reads a dump of an ESP32-family SPI flash, such as the output of
`esptool read-flash 0 ALL dump.bin` or `esptool merge-bin`, through
`inspect_artifact` and `extract_artifact`. The reader is static: no device,
esptool or ESP-IDF is needed, and no code is run.

The container format is `esp-flash-image`. Entries are the bootloader region,
the partition table sector and one file per partition. The bootloader and
each app partition are also decoded as [ESP images](esp-image.md), so their
headers, segments, integrity and descriptors appear in the root
`format_metadata`. Layout facts are cited to ESP-IDF v6.1
(`esp_flash_partitions.h`, `flash_partitions.c`, `gen_esp32part.py`,
`bootloader_common_loader.c`, `bootloader_utility.c` and each chip's
`esp_rom_caps.h`).

## Recognition

A file is a flash image when REA finds a partition table that ESP-IDF's
bootloader accepts (`esp_partition_table_verify`): 32-byte `0x50AA` entries,
at most one `0xEBEB` MD5 entry over the entries before it, and a terminating
entry within `0xC00` bytes. The table is located in this order:

1. at the caller's `partition_table_offset`, when given; no scan follows;
2. at the default `0x8000`;
3. by scanning every `0x1000`-aligned flash sector for a table whose MD5
   verifies. This location is derived, and the inventory says so.

Without a caller selection, the scan runs only when an ESP image sits at a
ROM bootloader offset, so ordinary files are not scanned. A C3 or S3 dump
begins with its bootloader, so flash layouts are detected before a file is
read as one ESP image. An image at another chip's ROM offset, such as an
ESP32 bootloader at the start of a dump read from `0x1000`, means the dump's
origin is not flash address 0. REA then does not scan, because a table found
that way would place every partition at the wrong file offset; pass
`flash_offset`.

When no table is found the layout is not recognized. This is an unknown
outcome, not a malformed file: flash encryption, which encrypts the
bootloader and the table, is one cause.

## Caller inputs

| Input                     | Meaning                                                                       |
| ------------------------- | ----------------------------------------------------------------------------- |
| `format: esp-flash-image` | Read the file as a flash dump; with no table found, refuse it                 |
| `flash_offset`            | Flash address (`0x…`) of the dump's first byte; default 0                     |
| `partition_table_offset`  | Flash address (`0x…`, a multiple of `0x1000`) of the table; disables the scan |

MCP takes these on `open_binary`; the CLI takes `--target-format
esp-flash-image`, `--flash-offset` and `--partition-table-offset` on
`inspect-artifact` and `extract-artifact`. The offsets require the format, and
the format takes no `architecture` or `entry_point`. The inputs are part of
the target's identity, so reopening the same bytes with other inputs reads
them again instead of reusing the earlier reading. The `open_binary` summary
reports them as `flash_offset` and `partition_table_offset`, null when
omitted.

## Layout facts

The root `format_metadata` (`esp-flash-image`) records:

- `flash_offset`: its `value` and whether the `caller` gave it or it is the
  `default`;
- `chip`: from the bootloader's `chip_id`, or null without a located
  bootloader;
- `bootloader`: the region from the chip's ROM bootloader offset to the
  table, with its ESP image facts;
- `partition_table`: its flash address, the `method` that found it
  (`default`, `caller` or `scan`), the partition count and the MD5 `status`
  (`valid`, `invalid` or `absent`) with the stored and computed digests;
- `apps`: ESP image facts for each app partition the dump holds;
- `otadata`: the OTA records and the derived selection;
- `partitions_outside_dump`: declared partitions with no bytes in the file;
- `undescribed`: byte ranges outside every region that are not erased flash.

The ROM loads the bootloader from `ESP_ROM_BOOTLOADER_OFFSET_FLASH`:
`0x1000` for ESP32 and ESP32-S2; `0x0` for ESP32-S3, C2, C3, C6, C61, H2 and
H21; and `0x2000` for ESP32-C5, H4, P4 and S31. A bootloader is located only
where its own `chip_id` says the ROM loads it.

### Partitions

Each partition entry is `partitions/<label>.bin` when the label is a safe,
unique name of letters, digits, `.`, `_` and `-` with at least one letter or
underscore, and `partitions/<index>.bin` otherwise; `source_path` keeps the
label. Its `format_metadata` (`esp-flash-partition`) records the table
`index`, `label` (null when not UTF-8), `type`, `subtype`, ESP-IDF's
`type_name` and `subtype_name`, `flash_address`, `size`, the `encrypted` and
`readonly` flags and any `unknown_flags`. The `encrypted` flag says how a
device with flash encryption stores the partition; it does not establish
that the dump's bytes are ciphertext.

A partition that the file holds only in part is the bytes the file holds,
with a limitation. One unreadable partition does not hide the others:
partitions outside the dump, before its first byte or overlapping another
are each reported while the rest stay readable.

### App partitions and the bootloader

Each app partition and the bootloader region carry ESP image `facts`:
`status` is `esp-image`, `erased` (the image header bytes are erased flash,
as in an empty OTA slot) or `unrecognized` (ciphertext or other data). For an
image they hold the [ESP image](esp-image.md) root facts, `segments`,
`signature_blocks`, `coverage` and `limitations`, with offsets relative to
the region. Extract a partition and inspect it as an ESP image for its
segments as entries.

### OTA data

The otadata partition holds two `esp_ota_select_entry_t` records, one at the
start of each 4 KiB sector. REA reports each record's `ota_seq`,
`seq_label`, `ota_state` and its name, `crc`, whether the CRC matches (CRC-32
of `ota_seq` seeded with `0xFFFFFFFF`) and whether the bootloader would treat
it as valid.

`selected` is derived as `bootloader_utility_get_selected_boot_partition`
does without app rollback or anti-rollback: the valid record with the higher
`ota_seq` selects slot `(ota_seq - 1) % ota_app_count`, indexed by OTA
subtype. With no usable record or no OTA app, the factory app is selected,
else `ota_0`. Its `assumptions` list what the derivation leaves out.
`running_partition` is always `unknown`: at boot the bootloader may first
mark a pending-verify record aborted, check the app's secure version against
eFuse, and fall back to another partition when an app fails to load.

## Coverage and extraction

Erased flash (`0xFF`) between regions is described; any other byte outside
the bootloader region, the table sector and the partitions is listed in
`undescribed` and makes coverage `unknown`. Coverage is also `unknown` when a
partition is truncated or outside the dump, or when no bootloader is
located.

`extract_artifact` writes every entry as an ordinary file, `nvs_keys`
partitions included. On a device without flash encryption an `nvs_keys`
partition holds the NVS encryption keys in plain text, and a dump of it
contains them. REA decrypts nothing, recovers no keys and does not interpret
NVS.

## Comparison

Artifact comparison uses each partition's `label`, `type`, `subtype`,
`flash_address`, `size` and flags as its declaration, so a partition that
moves or changes type with unchanged bytes is `changed` in `metadata`.
Partitions pair by path. The root facts derive from the dump's bytes, which
content comparison covers.

## Limits

- A flash dump inside another container, such as a ZIP, is classified from
  its first bytes and so reads as an ESP image, not as a flash layout; extract
  it first.
- ESP8266 dumps, Secure Boot v1 bootloader digests and flash-encrypted
  layouts are not read.
- NVS, FAT, SPIFFS and other data partitions are extracted, not decoded.
- An image nested in a partition is decoded for its facts; its segments are
  not inventory entries.

## Verification

Synthetic fixtures with computed MD5s and CRCs cover the table rules, every
way the table is located, the misplaced-origin guard, the ROM bootloader
offsets, overlaps, truncation and partitions outside the dump, index names
for unsafe labels, the otadata states and the bootloader's selection rules.
CLI and stdio MCP tests exercise the inputs, their identity, extraction and
comparison.
