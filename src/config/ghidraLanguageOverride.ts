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
