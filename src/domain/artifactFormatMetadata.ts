import { z } from "zod";

const offset = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const uint32 = z.number().int().min(0).max(0xffff_ffff);

/** Parsed source fields owned by the PCK adapter, independent of content hashes. */
export const godotPckMetadataSchema = z.strictObject({
  kind: z.literal("godot-pck"),
  format_version: uint32,
  engine_major: uint32,
  engine_minor: uint32,
  engine_patch: uint32,
  pack_start: offset,
  pack_end: offset,
  embedded: z.boolean(),
  pack_flags: uint32,
  file_base: offset,
  directory_start: offset,
  declared_file_count: uint32,
  directory_status: z.enum(["available", "encrypted", "sparse-bundle"]),
});
export type GodotPckMetadata = z.infer<typeof godotPckMetadataSchema>;

export const godotPckEntryMetadataSchema = z.strictObject({
  kind: z.literal("godot-pck-entry"),
  index: uint32,
  source_path: z.string(),
  declared_offset: offset,
  flags: uint32,
  md5_status: z.enum(["declared", "all-zero"]),
});

/** Source cookie fields and derived directory counts without Python execution. */
export const pyInstallerMetadataSchema = z.strictObject({
  kind: z.literal("pyinstaller"),
  layout_version: z.enum(["2.0", "2.1"]),
  archive_start: offset,
  archive_size: offset,
  cookie_offset: offset,
  toc_offset: offset,
  toc_size: offset,
  entry_count: offset,
  runtime_option_count: offset,
  external_dependency_count: offset,
  python_version_raw: uint32,
  python_major: uint32.nullable(),
  python_minor: uint32.nullable(),
  python_library: z.string().nullable(),
  encryption_marker_present: z.boolean(),
});
export type PyInstallerMetadata = z.infer<typeof pyInstallerMetadataSchema>;

/** Primitive facts preserve source spelling and keep metadata copies independent. */
export const pyInstallerEntryMetadataSchema = z.strictObject({
  kind: z.literal("pyinstaller-entry"),
  container: z.enum(["carchive", "pyz"]),
  container_name: z.string().nullable(),
  index: offset,
  source_name: z.string(),
  type_code: z.union([z.string().length(1), uint32]),
  relative_offset: offset,
  directory_record_offset: offset.nullable(),
  directory_record_size: offset.nullable(),
  compression_flag: z.union([z.literal(0), z.literal(1)]),
  bytecode_header: z.enum(["not-bytecode", "unknown", "derived"]),
  bytecode_magic: z
    .string()
    .regex(/^[0-9a-f]{8}$/u)
    .nullable(),
  pyz_status: z.enum(["not-pyz", "decoded", "opaque"]),
  pyz_sha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/u)
    .nullable(),
  pyz_python_magic: z
    .string()
    .regex(/^[0-9a-f]{8}$/u)
    .nullable(),
  pyz_python_version: z.string().nullable(),
  pyz_entry_count: offset.nullable(),
  encryption_source: z.literal("carchive-marker").nullable(),
  dependency_status: z
    .enum(["unresolved", "invalid-reference"])
    .exactOptional(),
  dependency_archive: z.string().nullable().exactOptional(),
  dependency_member: z.string().nullable().exactOptional(),
});
export type PyInstallerEntryMetadata = z.infer<
  typeof pyInstallerEntryMetadataSchema
>;

/**
 * Node.js single-executable blob facts. Lengths follow the Node 24 64-bit
 * little-endian `size_t` reader. The fuse sentinel is a separate carrier scan.
 */
export const nodeSeaMetadataSchema = z.strictObject({
  kind: z.literal("node-sea"),
  magic: z.literal(0x143da20),
  flags: uint32,
  disable_experimental_sea_warning: z.boolean(),
  use_snapshot: z.boolean(),
  use_code_cache: z.boolean(),
  include_assets: z.boolean(),
  include_exec_argv: z.boolean(),
  exec_argv_extension: z.enum(["none", "env", "cli"]),
  exec_argv: z.array(z.string()),
  code_path: z.string(),
  carrier: z.enum(["mach-o", "elf", "pe"]),
  blob_offset: offset,
  blob_length: offset,
  fuse_state: z.enum(["set", "unset", "absent", "conflicting"]),
  fuse_sentinel: z.string().nullable(),
  fuse_contradiction: z.string().nullable(),
});
export type NodeSeaMetadata = z.infer<typeof nodeSeaMetadataSchema>;

/** One injected script, snapshot, code cache, or asset. Bytes stay opaque. */
export const nodeSeaEntryMetadataSchema = z.strictObject({
  kind: z.literal("node-sea-entry"),
  role: z.enum(["main-script", "snapshot", "code-cache", "asset"]),
  source_path: z.string(),
  index: uint32,
});

/** Runtime member identity, independent of blob layout and directory order. */
export const nodeSeaEntryDeclaration = (
  metadata: z.infer<typeof nodeSeaEntryMetadataSchema>,
) => ({ role: metadata.role, source_path: metadata.source_path });

const uint8 = z.number().int().min(0).max(0xff);
const uint16 = z.number().int().min(0).max(0xffff);
const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/u);
const byteRange = z.strictObject({ offset, length: offset });

/** Derived from `chip_id` through the cited table. */
const espChipFactsSchema = z.strictObject({
  target: z.string(),
  isa: z.enum(["xtensa", "riscv"]),
  source: z.string(),
});

/** `esp_app_desc_t` fields, as ESP-IDF names them; strings stop at NUL. */
const espAppDescriptorSchema = z.strictObject({
  kind: z.literal("app"),
  offset,
  secure_version: uint32,
  version: z.string().nullable(),
  project_name: z.string().nullable(),
  time: z.string().nullable(),
  date: z.string().nullable(),
  idf_ver: z.string().nullable(),
  app_elf_sha256: sha256Hex,
  min_efuse_blk_rev_full: uint16,
  max_efuse_blk_rev_full: uint16,
  /** Stored as log2; 0 in images built before ESP-IDF v5.4. */
  mmu_page_size: uint8,
});

/** `esp_bootloader_desc_t` fields, as ESP-IDF names them. */
const espBootloaderDescriptorSchema = z.strictObject({
  kind: z.literal("bootloader"),
  offset,
  secure_version: uint8,
  version: uint32,
  idf_ver: z.string().nullable(),
  date_time: z.string().nullable(),
});

/**
 * ESP32-family image facts. `header` and the descriptor fields are observed;
 * the descriptor kind, `chip`, the integrity statuses and the trailing-byte
 * ranges are derived.
 */
export const espImageMetadataSchema = z.strictObject({
  kind: z.literal("esp-image"),
  /** `esp_image_header_t` fields, as ESP-IDF names them. */
  header: z.strictObject({
    segment_count: uint8,
    spi_mode: uint8,
    spi_speed: uint8,
    spi_size: uint8,
    entry_addr: uint32,
    wp_pin: uint8,
    spi_pin_drv: z.string().regex(/^[0-9a-f]{6}$/u),
    chip_id: uint16,
    min_chip_rev: uint8,
    min_chip_rev_full: uint16,
    max_chip_rev_full: uint16,
    reserved: z.string().regex(/^[0-9a-f]{8}$/u),
    hash_appended: z.boolean(),
  }),
  /** Derived from `chip_id` through the cited table; null for unknown IDs. */
  chip: espChipFactsSchema.nullable(),
  checksum: z.strictObject({
    offset: offset.nullable(),
    stored: uint8.nullable(),
    computed: uint8.nullable(),
    status: z.enum(["valid", "invalid", "unavailable"]),
  }),
  /** The SHA-256 the header's `hash_appended` adds after the checksum. */
  appended_sha256: z.strictObject({
    offset: offset.nullable(),
    stored: sha256Hex.nullable(),
    computed: sha256Hex.nullable(),
    status: z.enum(["valid", "invalid", "unavailable", "not-appended"]),
  }),
  /** End of the checksum block and any digest; null when truncated before it. */
  image_end: offset.nullable(),
  signature_sector_offset: offset.nullable(),
  /** Bytes after the image that no padding, signature or erased flash describes. */
  undescribed_trailing: z.array(byteRange),
  /** Its kind classifies the image as an app or a bootloader. */
  descriptor: z
    .discriminatedUnion("kind", [
      espAppDescriptorSchema,
      espBootloaderDescriptorSchema,
    ])
    .nullable(),
  /**
   * Set when the file is a flash dump read from a later flash address: this
   * image is not an app, its chip's ROM loads the bootloader from
   * `flash_offset`, and a partition table sits at `table_file_offset`, where
   * that origin puts the default `0x8000`. Reopen the file as
   * `esp-flash-image` with that `flash_offset`. Null otherwise, and in the
   * nested facts of a flash layout.
   */
  flash_dump: z
    .strictObject({ flash_offset: uint32, table_file_offset: offset })
    .nullable(),
});
export type EspImageMetadata = z.infer<typeof espImageMetadataSchema>;

/** One header-declared segment; `data_len` is declared, not available. */
export const espImageSegmentMetadataSchema = z.strictObject({
  kind: z.literal("esp-image-segment"),
  index: uint8,
  load_addr: uint32,
  data_len: uint32,
  header_offset: offset,
  /** ESP-IDF's cold-boot `should_map` and `should_load`; derived. */
  classification: z.enum(["mapped", "loaded", "not-loaded", "unknown"]),
});
export type EspImageSegmentMetadata = z.infer<
  typeof espImageSegmentMetadataSchema
>;

/**
 * What a segment header declares: where its bytes load and how many there
 * are. Header offsets are layout, and the classification is derived.
 */
export const espImageSegmentDeclaration = (
  metadata: EspImageSegmentMetadata,
) => ({ load_addr: metadata.load_addr, data_len: metadata.data_len });

/** One Secure Boot v2 block with its 0xE7 magic and a matching CRC32. */
export const espImageSignatureBlockMetadataSchema = z.strictObject({
  kind: z.literal("esp-image-signature-block"),
  /** Slot in the signature sector, 0 to 2. */
  index: uint8,
  version: uint8,
  scheme: z.enum(["rsa", "ecdsa"]).nullable(),
  /** Third block byte for ECDSA: 0 selects SHA-256, 1 SHA-384. */
  sha_version: uint8.nullable(),
  curve_id: uint8.nullable(),
  digest_algorithm: z.enum(["sha256", "sha384"]).nullable(),
  image_digest: z
    .string()
    .regex(/^(?:[0-9a-f]{64}|[0-9a-f]{96})$/u)
    .nullable(),
  /** Whether `image_digest` equals the digest of the bytes before the sector. */
  image_digest_matches: z.boolean().nullable(),
  /** SHA-256 of the block's public key, the value eFuse key digests hold. */
  public_key_sha256: sha256Hex.nullable(),
  /** REA checks no key, signature or eFuse. */
  signature_status: z.literal("unverified"),
});
export type EspImageSignatureBlockMetadata = z.infer<
  typeof espImageSignatureBlockMetadataSchema
>;

/** One partition table entry as declared, with ESP-IDF's type names. */
export const espFlashPartitionMetadataSchema = z.strictObject({
  kind: z.literal("esp-flash-partition"),
  /** Position among the table's partition entries. */
  index: uint8,
  /** The label up to its first NUL; null when it is not UTF-8. */
  label: z.string().nullable(),
  /** The label's bytes up to its first NUL in hex, when it is not UTF-8. */
  label_hex: z
    .string()
    .regex(/^(?:[0-9a-f]{2}){1,16}$/u)
    .nullable(),
  type: uint8,
  subtype: uint8,
  /** `gen_esp32part.py` names; null for values it does not name. */
  type_name: z.string().nullable(),
  subtype_name: z.string().nullable(),
  flash_address: uint32,
  size: uint32,
  encrypted: z.boolean(),
  readonly: z.boolean(),
  /** Flag bits other than `encrypted` and `readonly`, which ESP-IDF ignores. */
  unknown_flags: uint32,
  /**
   * Observed in the bytes the dump holds, from the partition's start: the
   * first byte that is not 0xFF and just past the last, null when every byte
   * is erased, and how many bytes are not 0xFF. All null for a partition the
   * dump holds none of.
   */
  written_offset: uint32.nullable(),
  written_end: uint32.nullable(),
  written_bytes: uint32.nullable(),
});
export type EspFlashPartitionMetadata = z.infer<
  typeof espFlashPartitionMetadataSchema
>;

/**
 * What a partition entry declares; its index is layout, and the written
 * fields are observed from its bytes, which content comparison covers.
 */
export const espFlashPartitionDeclaration = (
  metadata: EspFlashPartitionMetadata,
) => ({
  label: metadata.label,
  label_hex: metadata.label_hex,
  type: metadata.type,
  subtype: metadata.subtype,
  flash_address: metadata.flash_address,
  size: metadata.size,
  encrypted: metadata.encrypted,
  readonly: metadata.readonly,
  unknown_flags: metadata.unknown_flags,
});

/** ESP image facts for a region of a dump; offsets are relative to the region. */
const espFlashImageFactsSchema = z.strictObject({
  /** An ESP image, erased flash, or bytes that are not one, such as ciphertext. */
  status: z.enum(["esp-image", "erased", "unrecognized"]),
  image: espImageMetadataSchema.nullable(),
  segments: z.array(espImageSegmentMetadataSchema),
  signature_blocks: z.array(espImageSignatureBlockMetadataSchema),
  coverage: z.enum(["complete", "unknown"]).nullable(),
  limitations: z.array(z.string()),
});

const espOtaRecordSchema = z.strictObject({
  index: z.union([z.literal(0), z.literal(1)]),
  ota_seq: uint32,
  seq_label: z.string().regex(/^[0-9a-f]{40}$/u),
  ota_state: uint32,
  state_name: z
    .enum(["new", "pending-verify", "valid", "invalid", "aborted", "undefined"])
    .nullable(),
  crc: uint32,
  /** CRC-32 of `ota_seq` seeded with 0xFFFFFFFF, as the bootloader checks it. */
  crc_matches: z.boolean(),
  valid: z.boolean(),
});

/**
 * An ESP flash dump: where it sits in flash, its bootloader, partition table,
 * partitions and OTA data. Entries are the table's partitions; app and
 * bootloader regions carry their ESP image facts here.
 */
export const espFlashImageMetadataSchema = z.strictObject({
  kind: z.literal("esp-flash-image"),
  /** Flash address of the file's first byte: 0 unless the caller gave one. */
  flash_offset: z.strictObject({
    value: uint32,
    source: z.enum(["default", "caller"]),
  }),
  /** From the bootloader's `chip_id`; null without a located bootloader. */
  chip: espChipFactsSchema.nullable(),
  /** The image at its chip's ROM offset, through the partition table. */
  bootloader: z
    .strictObject({
      flash_address: uint32,
      region_size: offset,
      facts: espFlashImageFactsSchema,
    })
    .nullable(),
  partition_table: z.strictObject({
    flash_address: uint32,
    /** 0x8000, the caller's offset, or a scan for a verified MD5 (derived). */
    method: z.enum(["default", "caller", "scan"]),
    partition_count: uint8,
    md5: z.strictObject({
      status: z.enum(["valid", "invalid", "absent"]),
      stored: z
        .string()
        .regex(/^[0-9a-f]{32}$/u)
        .nullable(),
      computed: z
        .string()
        .regex(/^[0-9a-f]{32}$/u)
        .nullable(),
    }),
  }),
  /** Declared partitions with no bytes in the dump, which have no entry. */
  partitions_outside_dump: z.array(espFlashPartitionMetadataSchema),
  /** ESP image facts for each app partition the dump holds. */
  apps: z.array(
    z.strictObject({ partition_index: uint8, facts: espFlashImageFactsSchema }),
  ),
  /** The otadata partition the bootloader uses: the last one declared. */
  otadata: z
    .strictObject({
      partition_index: uint8,
      /** The records the dump holds, at most one per sector. */
      records: z.array(espOtaRecordSchema).max(2),
    })
    .nullable(),
  /**
   * The app the bootloader would select, derived for every table under the
   * stated assumptions. `basis` names the branch: `otadata`,
   * `factory-fallback` and `ota_0-fallback` from the otadata records,
   * `no-otadata` for a table without otadata (the factory index), `none`
   * for the bootloader's INVALID_INDEX, after which it resets, and
   * `unknown` when the dump lacks a record the bootloader reads.
   * `partition_index` is null when the table declares no partition for the
   * selected slot or fallback.
   */
  boot_selection: z.strictObject({
    basis: z.enum([
      "otadata",
      "factory-fallback",
      "ota_0-fallback",
      "no-otadata",
      "none",
      "unknown",
    ]),
    active_record: z.union([z.literal(0), z.literal(1)]).nullable(),
    slot: uint8.nullable(),
    partition_index: uint8.nullable(),
    assumptions: z.array(z.string()),
    /** Rollback, anti-rollback and load fallback decide it at boot. */
    running_partition: z.literal("unknown"),
  }),
  /**
   * Ranges outside every described region, each from a byte that is not
   * erased flash to the end of its gap.
   */
  undescribed: z.array(byteRange),
});
export type EspFlashImageMetadata = z.infer<typeof espFlashImageMetadataSchema>;

/** Declaration identity that is stable across archive layout changes. */
export const pyInstallerEntryDeclaration = (
  metadata: PyInstallerEntryMetadata,
) => ({
  container: metadata.container,
  container_name: metadata.container_name,
  source_name: metadata.source_name,
  type_code: metadata.type_code,
});

export const artifactFormatMetadataSchema = z.discriminatedUnion("kind", [
  godotPckMetadataSchema,
  godotPckEntryMetadataSchema,
  pyInstallerMetadataSchema,
  pyInstallerEntryMetadataSchema,
  nodeSeaMetadataSchema,
  nodeSeaEntryMetadataSchema,
  espImageMetadataSchema,
  espImageSegmentMetadataSchema,
  espImageSignatureBlockMetadataSchema,
  espFlashImageMetadataSchema,
  espFlashPartitionMetadataSchema,
]);
export type ArtifactFormatMetadata = z.infer<
  typeof artifactFormatMetadataSchema
>;
