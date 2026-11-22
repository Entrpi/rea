import type {
  ProviderLanguageRawBinaryTarget,
  RawBinaryLoad,
} from "./binaryTargetTypes.js";
import type { ProviderLanguageSelection } from "./providerLanguage.js";
import { admitRawBinary, parseRawBinaryEntryPoint } from "./rawBinary.js";

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

/** The first two M-profile vector-table words, little-endian. */
export const vectorTableWords = (
  initialStackPointer: number,
  reset: number,
): Uint8Array => {
  const words = new Uint8Array(8);
  const view = new DataView(words.buffer);
  view.setUint32(0, initialStackPointer, true);
  view.setUint32(4, reset, true);
  return words;
};

/** The load admission yields for a selection, reading `words` when Reset comes from the vector table. */
export const admittedRawLoad = (
  selection: Parameters<typeof admitRawBinary>[0],
  words?: Uint8Array,
): RawBinaryLoad => {
  const admitted = admitRawBinary(selection);
  if (!admitted.ok) throw new Error(admitted.error.reason);
  if (!("admit" in admitted.value)) return admitted.value.load;
  if (words === undefined)
    throw new Error("the selection reads Reset from the vector table");
  const finished = admitted.value.admit(words);
  if (!finished.ok) throw new Error(finished.error.reason);
  return finished.value.load;
};

/** A provider-language target as admission yields it for a 32-byte file by default. */
export const providerLanguageRawTarget = (
  providerLanguage: ProviderLanguageSelection,
  selection: {
    readonly entryPoint: string;
    readonly baseAddress?: string;
    readonly fileBytes?: number;
    readonly path?: string;
    readonly sha256?: string;
  },
): ProviderLanguageRawBinaryTarget => {
  const admitted = admitRawBinary({
    architecture: undefined,
    entryPoint: selection.entryPoint,
    ...(selection.baseAddress === undefined
      ? {}
      : { baseAddress: selection.baseAddress }),
    providerLanguage,
    fileBytes: selection.fileBytes ?? 32,
  });
  if (!admitted.ok) throw new Error(admitted.error.reason);
  if ("admit" in admitted.value || admitted.value.architecture !== null)
    throw new Error("expected a provider-language load");
  return {
    path: selection.path ?? "/fixture/firmware.bin",
    sha256: selection.sha256 ?? "a".repeat(64),
    kind: "executable",
    format: "raw-binary",
    availableArchitectures: [],
    rawLoad: admitted.value.load,
  };
};
