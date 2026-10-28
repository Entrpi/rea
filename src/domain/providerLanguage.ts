import { z } from "zod";

import {
  analysisProviderIdSchema,
  type AnalysisProviderSelector,
} from "./providerSelection.js";

/**
 * A provider's own decoder that the caller named for a raw image instead of a
 * provider-neutral family. The domain carries it unchanged and never reads
 * the language fields: the CLI and MCP contracts check each provider's
 * syntax, and only the named provider admits the language against its own
 * catalog.
 */
export interface ProviderLanguageSelection {
  readonly provider: string;
  readonly languageId: string;
  readonly compilerSpecId: string;
}

/** Persisted form in raw load identity. The language fields stay opaque here. */
export const providerLanguageIdentitySchema = z.strictObject({
  provider: analysisProviderIdSchema,
  language_id: z.string().min(1),
  compiler_spec_id: z.string().min(1),
});
export type ProviderLanguageIdentity = z.infer<
  typeof providerLanguageIdentitySchema
>;

/** The persisted form of a selection. */
export const providerLanguageIdentity = (
  selection: ProviderLanguageSelection,
): ProviderLanguageIdentity => ({
  provider: selection.provider,
  language_id: selection.languageId,
  compiler_spec_id: selection.compilerSpecId,
});

/**
 * A provider language applies only when the caller selects its provider
 * explicitly. Automatic selection and other providers refuse it, so a
 * language never reaches a provider whose vocabulary it is not.
 */
export const providerLanguageProviderIssue = (
  selection: ProviderLanguageSelection | undefined,
  provider: AnalysisProviderSelector | undefined,
): string | undefined =>
  selection === undefined || provider === selection.provider
    ? undefined
    : `provider_language names ${selection.provider}; provider_id must select ${selection.provider}${
        provider === undefined || provider === "auto"
          ? " explicitly, not automatic selection"
          : `, not ${provider}`
      }`;
