/**
 * Explicit Ghidra import language for targets whose header cannot identify the
 * producing compiler, such as Borland-built PE images.
 */
export interface GhidraLanguageOverride {
  /** Ghidra language ID: `processor:endian:size:variant`. */
  readonly languageId: string;
  /** Ghidra compiler-spec ID; absent selects the language's default spec. */
  readonly compilerSpecId?: string;
}

/**
 * Whether a caller-selected language asks for a lane's pinned one: the same
 * language, with the same compiler specification or none.
 */
export const ghidraLanguageOverrideMatches = (
  override: GhidraLanguageOverride,
  pinned: GhidraLanguageOverride,
): boolean =>
  override.languageId === pinned.languageId &&
  (override.compilerSpecId === undefined ||
    override.compilerSpecId === pinned.compilerSpecId);
