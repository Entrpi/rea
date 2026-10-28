# UF2 and DfuSe images

REA inventories UF2 (Microsoft's USB Flashing Format) and DfuSe (ST's DFU
update container, `.dfu`) files through `inspect-artifact` /
`inspect_artifact`, and materializes their decoded bytes through
`extract-artifact` / `extract_artifact`. UF2 is the drag-and-drop format of the
RP2040 and RP2350 bootloaders, of TinyUF2 on ESP32-S2 and ESP32-S3, and of
`esptool merge-bin --format uf2`. Decoding is static and needs no external tool.

```sh
rea inspect-artifact ./firmware.uf2 --json
rea inspect-artifact ./firmware.dfu --detail summary --evidence_output evidence.json --json
rea extract-artifact ./firmware.uf2 --json
```

For MCP, open the file with `open_binary`, then call `inspect_artifact`. Summary
delivery retains the complete Evidence; use `parent_evidence_id` with
`inspect_analysis_view` to read selected regions and fields. `extract_artifact`
returns a fresh `output_root` containing one raw file per region.

## Recognition

A file is UF2 only when its first 512 bytes are a complete block with all three
magic numbers: `0x0A324655` and `0x9E5D5157` at the start and `0x0AB16F30` at
the end. A file is DfuSe only when it begins with `DfuSe` and format version 1
and ends with a 16-byte DFU 1.1a suffix: `bcdDFU` `0x011A`, the `UFD` signature
and `bLength` 16. The suffix CRC is not part of recognition. The file name does
not matter, and a file with only one of the DfuSe markers stays unrecognized.
The container formats are `uf2` and `dfuse`.

## UF2 regions and metadata

Each entry is one address-contiguous region of one family's main-flash
payloads, named `family-0x<familyID>/0x<start>-0x<end>.bin` with an inclusive
end address, for example `family-0xe48bff56/0x10000000-0x1000ffff.bin`. Blocks
without the familyID flag (`0x2000`) go under `no-family/`. Families are
separate address spaces: a multi-family file, such as a Pico SDK image for both
RP2040 and RP2350, has a region per family even at the same addresses. Gaps are
never filled.

Region `format_metadata` (`uf2-region`) records `family_id` (or `null`),
`family_name`, `start_address`, `end_address`, `length`, `block_count`, and
`first_block`/`last_block`: the zero-based file positions of the contributing
blocks. `family_name` is the short name from a small table copied from
Microsoft's `uf2families.json` at commit
[`cf3bd7f9`](https://github.com/microsoft/uf2/blob/cf3bd7f9c274b949528f8cd6a19eef2502a687d2/utils/uf2families.json).
It covers the ESP32 family, ESP8266, RP2040, the RP2350 and RP2XXX download
families, STM32F4, nRF52840, SAMD21 and SAMD51. Other IDs keep their value with
`family_name: null`. A familyID names a target family; it does not establish
the CPU state, memory map or entry point.

Root `format_metadata` (`uf2`) records:

| Field                                                      | Meaning                                                                                        |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `block_count`, `trailing_bytes`                            | Complete 512-byte blocks, and bytes after the last complete block                              |
| `invalid_block_count`                                      | Blocks with a wrong magic number, a payload over 476 bytes, or a payload that wraps past 4 GiB |
| `flash_block_count`                                        | Valid main-flash blocks, the only source of region bytes                                       |
| `not_main_flash_block_count`, `file_container_block_count` | Blocks with flag `0x1`, and blocks with flag `0x1000`                                          |
| `md5_block_count`, `extension_tag_block_count`             | Blocks that declare an MD5 region (`0x4000`) or extension tags (`0x8000`)                      |
| `family_count`                                             | Distinct familyIDs among main-flash blocks                                                     |
| `sequence_count`                                           | Numbering sequences: valid blocks grouped by familyID and declared block count                 |
| `missing_block_count`                                      | Block numbers below a sequence's block count that no valid block carries                       |
| `repeated_block_count`, `out_of_order_block_count`         | Blocks whose number already appeared, and blocks numbered at or below their predecessor        |
| `block_number_out_of_range_count`                          | Blocks numbered at or above their block count, or with a block count of 0                      |
| `region_count`, `data_bytes`, `duplicate_bytes`            | Regions, unique decoded bytes, and bytes rewritten with identical values                       |

Numbering is counted per familyID because a bootloader ignores every field of
another family's block, including its numbering. esptool numbers each merged
input file from 0, so its files are separate sequences of one family.

## UF2 facts, limitations and failures

| Situation                                                    | Outcome                                                                             |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| Blocks out of address or number order                        | Sorted into regions; counted in `out_of_order_block_count`                          |
| An address written twice with the same value in one family   | Accepted and counted in `duplicate_bytes`                                           |
| An address written twice with different values in one family | Fails, naming the family, the address and the block spans of both writes            |
| The same addresses in different families                     | Separate regions; never a conflict                                                  |
| Numbered blocks absent from a sequence                       | Regions are returned; coverage is unknown and a limitation names the sequences      |
| An invalid block                                             | Excluded; coverage is unknown and a limitation names the first one and its offset   |
| A partial final block                                        | Excluded; coverage is unknown and the file may be truncated                         |
| Block numbers at or above the block count                    | Payloads are kept; coverage is unknown                                              |
| Not-main-flash blocks (`0x1`)                                | Excluded from regions and reported with their payload bytes; coverage is unaffected |
| File-container blocks (`0x1000`)                             | Excluded from regions; their files are not reconstructed, so coverage is unknown    |
| MD5 (`0x4000`) and extension-tag (`0x8000`) blocks           | Counted; the MD5 regions and tags are not decoded or verified                       |

The MD5 structure is not verified because producers disagree on its place:
the specification puts it in the last 24 bytes of the data area, while
esptool v4.12.0 and v5.6.0 write it right after a shorter final payload and
leave those 24 bytes zero.

## DfuSe regions and metadata

Each element is one entry at its own file range, named
`target-<t>/element-<e>-0x<start>-0x<end>.bin` with zero-based target and
element indexes, for example `target-0/element-0-0x08000000-0x0800ffff.bin`.
Elements are never merged. Each occurrence's `source_location` is the byte range
of the element data in the file.

Element `format_metadata` (`dfuse-element`) records `target_index`,
`alternate_setting`, `target_name`, `element_index`, `start_address`,
`end_address` and `length`. `target_name` is `null` when `bTargetNamed` is 0;
otherwise it is `szTargetName` up to its first NUL, one character per byte.

Root `format_metadata` (`dfuse`) records:

| Field                                                      | Meaning                                                                         |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `format_version`, `image_size`, `target_count`             | `bVersion`, `DFUImageSize` and `bTargets` from the prefix                       |
| `element_count`, `empty_element_count`, `data_bytes`       | All elements, elements of 0 bytes (which have no entry), and element data bytes |
| `overlapping_element_count`                                | Elements that overlap an earlier element of the same alternate setting          |
| `device_version`, `product_id`, `vendor_id`, `dfu_version` | `bcdDevice`, `idProduct`, `idVendor` and `bcdDFU` from the suffix               |
| `suffix_crc`, `computed_crc`                               | The stored `dwCRC`, and the same CRC computed over every byte before it         |

The DFU suffix CRC is CRC-32 without the final inversion, as dfu-util stores
and checks it.

## DfuSe facts, limitations and failures

| Situation                                                                                   | Outcome                                                                   |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `dwCRC` differs from the computed CRC                                                       | Follows `integrity_policy`, below                                         |
| A target without the `Target` signature                                                     | Fails with its byte offset                                                |
| `DFUImageSize`, a target size or an element size that disagrees with the bytes that hold it | Fails with the byte offset and the declared and available sizes           |
| An element whose address range wraps past `0xFFFFFFFF`                                      | Fails with its byte offset                                                |
| Overlapping elements of one alternate setting                                               | Kept as separate entries; a limitation names them; coverage is unaffected |
| The same addresses in different alternate settings                                          | Separate entries; an alternate setting selects a device memory            |
| Elements of 0 bytes                                                                         | Counted in `empty_element_count`; no entry                                |

A CRC mismatch is an integrity contradiction, never proof of a cause. With the
default `integrity_policy` `fail`, inspection and extraction fail with
`artifact_integrity_mismatch`, whose details carry `algorithm: "dfu-crc32"`,
`declared_crc32` and `calculated_crc32`. With `record-and-continue`
(CLI `--integrity-policy record-and-continue`), the root occurrence becomes
`mismatched`, `integrity_contradictions` records the pair for logical path `.`,
and extraction carries that contradiction, because every element came from the
contradicted container.

## Limits

Each file must be at most 128 MiB. The UF2 decoder reserves at most 476 bytes
per complete block before reading and retains at most 65,536
address-discontiguous block runs. The DfuSe decoder holds the file once and
parses at most 65,536 elements, empty ones included. These are fixed resource
bounds, not format limits, and fail as limits (`file-size` and `capacity`) with
no runtime override. Configurable ceilings are tracked in
[#6176](https://github.com/morluto/rea/issues/6176).

Decoded regions are cached only for the reader's lifetime, and each open checks
the admitted carrier identity again. These readers share the Intel HEX
reader's region streams, cancellation and close behavior.

## Analyzing a region

Inventory does not establish the CPU, byte order or memory map, or an entry
point. To disassemble a region, extract it and open the region file with
`open_binary` using format `raw-binary`, an architecture you choose, and
`entry_point` set to the region start address; raw-binary maps file offset 0 at
`entry_point`. Each region is opened separately, so references between regions
are not resolved.

## Verification

Fixtures written from the UF2 specification and from ST UM0391 cover block and
element layouts, numbering, families, rewrites and conflicts, invalid and
partial blocks, not-main-flash and file-container blocks, structural faults,
overlaps, both integrity policies, resource refusals, inventory, extraction and
reader identity checks. One DfuSe fixture is byte-identical to the output of a
Python 3 transcription of dfu-util's `dfuse-pack.py`, including its CRC. CLI and
stdio MCP tests exercise the same artifact provider and advertised schemas.

`npm run verify:uf2` runs esptool's `merge-bin --format uf2` on generated
inputs at known addresses, with and without MD5 and with 256-byte payloads, and
on a concatenation of two chips' outputs. Inspection and extraction must return
every input at its address under esptool's own familyID. It passed with esptool
v4.12.0 and v5.6.0 on macOS. Set `REA_ESPTOOL_PYTHON` to a Python that runs
`-m esptool`. Pico SDK, picotool, `uf2conv.py`, TinyUF2 and real DfuSe producers
remain unverified, and no device accepted these files in REA's tests.
