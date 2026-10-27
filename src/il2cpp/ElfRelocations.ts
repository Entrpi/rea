import {
  readElfPointerRelocationsSteps,
  ElfPointerRelocationFailure,
} from "../native/metadata/ElfPointerRelocations.js";
import type {
  BinaryContainer,
  FileMapping,
  ZeroFillMapping,
} from "../native/metadata/BinaryContainer.js";
import { Il2cppBinaryFormatFailure } from "./Il2cppBinaryFormat.js";

/** Materialize the shared loader facts only for IL2CPP's existing private reader. */
export function* applyElfRelativeRelocationsSteps(
  image: Buffer,
  elf: Extract<BinaryContainer, { format: "elf" }>["elf"],
  mappings: readonly FileMapping[],
  zeroFills: readonly ZeroFillMapping[],
): Generator<
  void,
  {
    readonly bytes: Buffer;
    readonly unresolved: ReadonlyMap<bigint, number>;
    readonly zeroFillPointers: ReadonlyMap<bigint, bigint>;
  }
> {
  try {
    const overlay = yield* readElfPointerRelocationsSteps(
      image,
      {
        bits: 64,
        little: true,
        machine: elf.machine,
        dynamicSegments: elf.dynamicSegments,
        mappings,
        zeroFills,
      },
      { requireDynamic: true },
    );
    yield;
    const bytes = Buffer.from(image),
      zeroFillPointers = new Map<bigint, bigint>();
    for (const write of overlay.writes) {
      const at = write.file_offset;
      if (write.value === null) {
        if (at !== null) bytes.fill(0, at, at + write.width);
      } else if (at === null) zeroFillPointers.set(write.address, write.value);
      else bytes.writeBigUInt64LE(write.value, at);
    }
    return { bytes, unresolved: overlay.unresolved, zeroFillPointers };
  } catch (cause) {
    if (cause instanceof ElfPointerRelocationFailure)
      throw new Il2cppBinaryFormatFailure(cause.reason, cause.message);
    throw cause;
  }
}
