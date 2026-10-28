import { z } from "zod";
import { err, ok, type Result } from "./result.js";

/**
 * Interpretation explicitly selected by the caller. DOL has no magic, so
 * `gamecube-dol` is never auto-detected; an ESP8266 image shares the 0xE9
 * magic of ESP32-family images, so `esp8266-image` is never auto-detected.
 */
export const executableFormatHintSchema = z.enum([
  "dos-com",
  "raw-binary",
  "gamecube-dol",
  "esp8266-image",
]);
/** Explicit interpretation for formats whose bytes do not identify them. */
export type ExecutableFormatHint = z.infer<typeof executableFormatHintSchema>;

/**
 * Explicit formats that select an archive reading the bytes cannot
 * establish, so artifact inventory reads the root as the caller named it.
 */
export const CALLER_SELECTED_ROOT_FORMATS = [
  "esp8266-image",
] as const satisfies readonly ExecutableFormatHint[];
export type CallerSelectedRootFormat =
  (typeof CALLER_SELECTED_ROOT_FORMATS)[number];

/** The caller-selected root format a target format names, if any. */
export const callerSelectedRootFormat = (
  format: string,
): CallerSelectedRootFormat | undefined =>
  CALLER_SELECTED_ROOT_FORMATS.find((selected) => selected === format);

/** Validate the single 64 KiB COM segment, excluding its 256-byte PSP prefix. */
export const validateDosComLength = (length: number): Result<null, string> =>
  Number.isSafeInteger(length) && length >= 1 && length <= 0xff00
    ? ok(null)
    : err(
        "DOS COM requires 1..65280 file bytes (64 KiB segment minus the 256-byte PSP prefix)",
      );
