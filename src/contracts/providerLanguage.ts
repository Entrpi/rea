import { z } from "zod";

import type { ProviderLanguageSelection } from "../domain/providerLanguage.js";

// Ghidra language IDs are four colon-separated fields; variants may contain
// spaces ("x86:LE:16:Real Mode") but never leading or trailing whitespace.
// Stock .ldefs also use "/" in processors ("M16C/60") and LEBE for ARM BE8
// (big-endian data, little-endian instructions).
export const ghidraLanguageIdSchema = z
  .string()
  .regex(
    /^[A-Za-z0-9_.+-]+(?:\/[A-Za-z0-9_.+-]+)*:(?:LE|BE|LEBE):[1-9]\d*:[A-Za-z0-9_.+-](?:[A-Za-z0-9_.+ -]*[A-Za-z0-9_.+-])?$/u,
    "must be a Ghidra language ID such as x86:LE:32:default",
  );

export const ghidraCompilerSpecIdSchema = z
  .string()
  .regex(
    /^[A-Za-z0-9_.+-]+$/u,
    "must be a Ghidra compiler-spec ID such as default or borlandcpp",
  );

/**
 * A provider's own decoder for a raw image that no provider-neutral family
 * describes. The object names its provider and uses that provider's
 * vocabulary; only that provider admits it, against its installed catalog.
 * Ghidra is the only provider today, so the object has one shape; another
 * provider would add a member discriminated by `provider`.
 */
export const providerLanguageInputSchema = z.strictObject({
  provider: z
    .literal("ghidra")
    .describe("Provider whose language catalog defines the language."),
  language_id: ghidraLanguageIdSchema.describe(
    "Ghidra language ID from an .ldefs file of the installation, such as SuperH4:LE:32:default.",
  ),
  compiler_spec_id: ghidraCompilerSpecIdSchema.describe(
    "Compiler spec ID that the language's .ldefs entry declares, such as default.",
  ),
});
export type ProviderLanguageInput = z.infer<typeof providerLanguageInputSchema>;

/** Carry the caller's provider language into target admission unchanged. */
export const providerLanguageSelection = (
  input: ProviderLanguageInput,
): ProviderLanguageSelection => ({
  provider: input.provider,
  languageId: input.language_id,
  compilerSpecId: input.compiler_spec_id,
});
