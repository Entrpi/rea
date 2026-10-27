import type { RawBinaryLoad } from "./binaryTargetTypes.js";
import { parseRawBinaryEntryPoint } from "./rawBinary.js";

/** The load raw-binary admission yields for a caller entry: file offset 0 maps at the entry. */
export const rawLoadAtEntry = (entryPoint: string): RawBinaryLoad => {
  const parsed = parseRawBinaryEntryPoint(entryPoint);
  if (!parsed.ok) throw new Error(parsed.error);
  return {
    baseAddress: parsed.value.canonical,
    entryPoint: parsed.value.canonical,
    entrySource: { kind: "caller" },
  };
};
