import type { ArtifactReaderAdmission } from "../ArtifactReaderAdmission.js";
import type { AsarHeaderAdmission } from "../../config/asarHeaderAdmission.js";
import type {
  ArtifactReader,
  ArtifactReaderTraversal,
} from "../ArtifactReader.js";
import { createArtifactReader } from "../createArtifactReader.js";
import type {
  ArtifactInventoryCoverage,
  ArtifactOccurrence,
} from "../../domain/artifactGraph.js";
import {
  isZipPackageFormat,
  ZIP_NON_ENTRY_LIMITATION,
} from "../../domain/zipPackageFormat.js";
import { ESP_IMAGE_LIMITATIONS } from "../../domain/firmware/espImageFacts.js";

export const createReader = (
  path: string,
  format: ArtifactOccurrence["artifact_format"],
  environment: Readonly<NodeJS.ProcessEnv>,
  readerAdmission?: ArtifactReaderAdmission,
  asarHeaderAdmission?: AsarHeaderAdmission,
  selectedPath?: string,
): ArtifactReader | undefined => {
  if (
    (format === "mach-o-universal" || format === "dmg") &&
    process.platform !== "darwin"
  )
    return undefined;
  return createArtifactReader(path, format, {
    environment,
    unreadableDirectories: "omit",
    admission: readerAdmission,
    asarHeaderAdmission,
    selectedPath,
  });
};

/** Decide traversal scope and availability once, independently of diagnostic wording. */
export const inventoryCoverage = (
  format: ArtifactOccurrence["artifact_format"],
  reader: ArtifactReader | undefined,
  traversal: ArtifactReaderTraversal,
): {
  readonly coverage: ArtifactInventoryCoverage;
  readonly limitations: string[];
} => {
  if (reader !== undefined)
    return {
      coverage: { scope: "container-entries", status: traversal.status },
      limitations: [
        ...(isZipPackageFormat(reader.format)
          ? [ZIP_NON_ENTRY_LIMITATION]
          : []),
        ...(reader.format === "godot-pck"
          ? [
              "PCK inventory establishes packaged bytes and metadata; scenes, binary resources, GDScript bytecode and runtime signal behavior were not decoded.",
            ]
          : []),
        ...(reader.format === "unityfs"
          ? [
              "UnityFS inventory establishes packaged bytes and metadata; serialized objects, textures, meshes and runtime asset behavior were not decoded. LZMA-compressed members are unsupported.",
            ]
          : []),
        ...(reader.format === "node-sea"
          ? [
              "Node SEA inventory establishes the injected blob, flags, fuse sentinel, main script, optional code cache, snapshot, and assets. V8 snapshots and code cache are not deserialized, and the application is not executed.",
            ]
          : []),
        ...(reader.format === "intel-hex" || reader.format === "srec"
          ? [
              "Intel HEX/S-record inventory decodes data records into address-contiguous regions. It does not establish CPU, byte order, memory map, or that a declared start address is executable; gaps are unwritten, not zero.",
            ]
          : []),
        ...(reader.format === "esp-flash-image"
          ? [
              "ESP flash layout inventory reads a dump's bootloader region, partition table and partitions and decodes the bootloader and app partitions as ESP images. The OTA selection is derived without app rollback or anti-rollback, and the running partition is unknown. Partitions, nvs_keys included, are extracted as ordinary data; nothing is decrypted.",
            ]
          : []),
        ...(reader.format === "esp-image"
          ? [ESP_IMAGE_LIMITATIONS.inventoryScope]
          : []),
        ...(reader.format === "uimage"
          ? [
              "uImage inventory establishes the 64-byte legacy header facts and stored payload bytes. Compressed payloads are not decompressed, and the image is not executed.",
            ]
          : []),
        ...(reader.format === "uf2"
          ? [
              "UF2 inventory decodes main-flash block payloads into address-contiguous regions per familyID. It does not establish CPU, byte order, memory map, or an entry point; a familyID names a target family, and gaps are unwritten, not zero.",
            ]
          : []),
        ...(reader.format === "dfuse"
          ? [
              "DfuSe inventory lists each target element as one region at its declared address. It does not establish CPU, byte order, memory map, or an entry point; an alternate setting selects a device memory, not an address space REA can interpret.",
            ]
          : []),
        ...(reader.format === "fit"
          ? [
              "FIT inventory reports each /images node's stored bytes and its declared type, architecture, OS, compression, load and entry. Image data is not decompressed or decrypted, signatures are not verified, nothing is executed, and load and entry addresses are declarations.",
            ]
          : []),
        ...traversal.limitations,
      ],
    };
  // dmg and pkg reach here only after classifyRootFormat matched their bytes.
  if (format === "dmg" || format === "pkg")
    return {
      coverage: { scope: "container-entries", status: "unknown" },
      limitations: [
        `${format.toUpperCase()} root hash is observed; child inventory requires a native macOS adapter.`,
      ],
    };
  if (format === "mach-o-universal")
    return {
      coverage: { scope: "container-entries", status: "unknown" },
      limitations: [
        "Universal Mach-O slices require the native macOS lipo adapter.",
      ],
    };
  if (
    isZipPackageFormat(format) ||
    format === "directory" ||
    format === "asar" ||
    format === "godot-pck" ||
    format === "unityfs" ||
    format === "uimage" ||
    format === "node-sea" ||
    format === "intel-hex" ||
    format === "srec" ||
    format === "esp-image" ||
    format === "esp-flash-image" ||
    format === "uf2" ||
    format === "dfuse" ||
    format === "fit"
  )
    return {
      coverage: { scope: "container-entries", status: "unknown" },
      limitations: [`${format} child inventory reader is unavailable.`],
    };
  return {
    coverage: { scope: "root", status: "complete" },
    limitations: [
      "Inventory covers root bytes only; child container entries were not examined.",
    ],
  };
};
