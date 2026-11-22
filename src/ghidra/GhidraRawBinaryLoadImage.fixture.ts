import { createHash } from "node:crypto";

import type { NativeLoadImageObservation } from "../domain/native/nativeLoadImage.js";
import type { ArchitectureVariant } from "../domain/architectureVariant.js";
import type {
  FamilyRawBinaryTarget,
  RawBinaryLoad,
  RawBinaryTarget,
} from "../domain/binaryTargetTypes.js";
import { rawLoadAtEntry } from "../domain/rawBinary.fixture.js";
import { ghidraRawBinaryLanguage } from "./GhidraRawBinaryLanguage.js";

const hash = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

/** An ARM image of one `bx lr`, the default raw-binary file. */
export const armBxLrImage = (): Buffer => Buffer.from("1eff2fe1", "hex");

/**
 * A raw-binary target, its snapshot facts and the import Ghidra reports for
 * it, all derived from `bytes` mapped at the load's base. A load with a
 * provider language names no family; any other load is an ARM-family target.
 * The default is a legacy load of an ARM `bx lr` at its entry.
 */
export const fixtureRawBinaryLoadImage = (
  bytes: Buffer = armBxLrImage(),
  rawLoad: RawBinaryLoad = rawLoadAtEntry("0x8000000"),
): {
  snapshot: { sha256: string; bytes: number };
  target: RawBinaryTarget;
  observation: NativeLoadImageObservation;
} => {
  const digest = hash(bytes);
  const last = BigInt(rawLoad.baseAddress) + BigInt(bytes.length) - 1n;
  const identity = {
    path: "/tmp/ecu.bin",
    sha256: digest,
    kind: "executable",
    format: "raw-binary",
  } as const;
  const { providerLanguage, lastAddress } = rawLoad;
  const target: RawBinaryTarget =
    providerLanguage === undefined || lastAddress === undefined
      ? {
          ...identity,
          architecture: "arm",
          availableArchitectures: ["arm"],
          rawLoad,
        }
      : {
          ...identity,
          availableArchitectures: [],
          rawLoad: { ...rawLoad, providerLanguage, lastAddress },
        };
  const language = ghidraRawBinaryLanguage(target);
  // A family pins its default space; a caller-selected language does not.
  const space = language.defaultAddressSpace ?? "ram";
  return {
    snapshot: { sha256: digest, bytes: bytes.length },
    target,
    observation: {
      executable_format: "Raw Binary",
      language_id: language.languageId,
      compiler_spec_id: language.compilerSpecId,
      image_base: "0x0",
      default_address_space: space,
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
          start: rawLoad.baseAddress,
          end: `0x${last.toString(16)}`,
          address_space: space,
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
      entry_points: [rawLoad.entryPoint],
      entry_context: [],
    },
  };
};

/** A 6809 image for caller-selected-language loads: nop; nop; bra . */
export const m6809Image = (): Buffer => Buffer.from("121220fe", "hex");

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
