import type { RizinInput } from "../domain/reverseEngineering.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";

export const RIZIN_PROVIDER_IDENTITY = {
  id: "rizin",
  name: "Rizin",
  version: null,
} as const;

/** Default one-shot presentation to plain text while retaining plugin availability. */
export const rizinCommand = (input: RizinInput): readonly string[] => [
  "-N",
  "-q",
  "-e",
  "scr.color=0",
  // Rizin 0.9.1 refuses -e asm.arch= and -e asm.bits= at startup. Once the
  // file is open it applies -a and -b, then the -e settings.
  ...(input.asm_arch === undefined ? [] : ["-a", input.asm_arch]),
  ...(input.asm_bits === undefined ? [] : ["-b", String(input.asm_bits)]),
  ...(input.asm_cpu === undefined ? [] : ["-e", `asm.cpu=${input.asm_cpu}`]),
  ...(input.base_address === undefined ? [] : ["-m", input.base_address]),
  "-c",
  input.command,
  absoluteCallerPath(input.path),
];

/** What REA cannot attest about the decoder and map inputs it passed to Rizin. */
export const rizinCommandLimitations = (
  input: RizinInput,
): readonly string[] =>
  input.asm_arch === undefined &&
  input.asm_bits === undefined &&
  input.asm_cpu === undefined &&
  input.base_address === undefined
    ? []
    : [
        "REA passed the selected asm_* and base_address values to Rizin unchecked. Rizin uses another value for one it cannot apply, at most reporting it on stderr, and its loader decides the map for a format it loads from headers. REA does not confirm the decoder or map that Rizin used.",
      ];
