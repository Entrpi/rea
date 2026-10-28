import { z } from "zod";
import { err, ok, type Result } from "./result.js";
import { targetFormatIds } from "./targetFormats.js";

/**
 * Executable interpretation explicitly selected by the caller. DOL has no magic,
 * so `gamecube-dol` is never auto-detected.
 */
export const executableFormatHintSchema = z.enum(
  targetFormatIds("selectable", true),
);
/** Explicit executable interpretation for formats with no identifying header. */
export type ExecutableFormatHint = z.infer<typeof executableFormatHintSchema>;

/** Validate the single 64 KiB COM segment, excluding its 256-byte PSP prefix. */
export const validateDosComLength = (length: number): Result<null, string> =>
  Number.isSafeInteger(length) && length >= 1 && length <= 0xff00
    ? ok(null)
    : err(
        "DOS COM requires 1..65280 file bytes (64 KiB segment minus the 256-byte PSP prefix)",
      );
