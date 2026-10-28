import { createHash } from "node:crypto";

import type { NativeLoadImageObservation } from "../domain/native/nativeLoadImage.js";
import type { ArchitectureVariant } from "../domain/architectureVariant.js";
import type {
  FamilyRawBinaryTarget,
  RawBinaryTarget,
} from "../domain/binaryTargetTypes.js";
import { rawLoadAtEntry } from "../domain/rawBinary.fixture.js";

const hash = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

export const fixtureRawBinaryLoadImage = (): {
  snapshot: { sha256: string; bytes: number };
  target: FamilyRawBinaryTarget;
  observation: NativeLoadImageObservation;
} => {
  const bytes = Buffer.from("1eff2fe1", "hex");
  const digest = hash(bytes);
  return {
    snapshot: { sha256: digest, bytes: bytes.length },
    target: {
      path: "/tmp/ecu.bin",
      sha256: digest,
      kind: "executable",
      format: "raw-binary",
      architecture: "arm",
      availableArchitectures: ["arm"],
      rawLoad: {
        baseAddress: "0x8000000",
        entryPoint: "0x8000000",
        entrySource: { kind: "caller" },
      },
    },
    observation: {
      executable_format: "Raw Binary",
      language_id: "ARM:LE:32:v7",
      compiler_spec_id: "default",
      image_base: "0x0",
      default_address_space: "ram",
      source_files: [
        {
          name: "ecu.bin",
          size: bytes.length,
          original_sha256: digest,
          modified_sha256: digest,
        },
      ],
      mappings: [
        {
          block: "ram",
          start: "0x8000000",
          end: "0x8000003",
          address_space: "ram",
          initialized: true,
          loaded: true,
          overlay: false,
          readable: true,
          writable: false,
          executable: true,
          length: bytes.length,
          source_file_index: 0,
          file_offset: 0,
          sha256: digest,
        },
      ],
      relocations: [],
      entry_points: ["0x8000000"],
      entry_context: [],
    },
  };
};

/** A family raw target at 0x0, for bindings that read only the family and variant. */
export const familyRawTarget = (
  architecture: FamilyRawBinaryTarget["architecture"],
  architectureVariant?: ArchitectureVariant,
): RawBinaryTarget => ({
  path: "/tmp/image.bin",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "raw-binary",
  architecture,
  availableArchitectures: [architecture],
  rawLoad: {
    ...rawLoadAtEntry("0x0"),
    ...(architectureVariant === undefined ? {} : { architectureVariant }),
  },
});
