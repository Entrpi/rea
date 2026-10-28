import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { digestSchema } from "../domain/digests.js";
import { parseXmlDocument } from "../domain/xmlDocument.js";
import { decodeXmlPlistText } from "../domain/propertyListXmlText.js";

import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { withArtifactRegularFile } from "../artifacts/ArtifactFileOperation.js";
import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import { readBoundedFileBytes } from "../process/BoundedFileBytes.js";

/**
 * Files of a language definition that decide how Ghidra decodes, in the order
 * the profile commits them and the raw prepare script checks them. The
 * `.ldefs` entry names the other three, which Ghidra resolves beside it.
 */
export const GHIDRA_LANGUAGE_DEFINITION_FILES = [
  { role: "ldefs", source: "the .ldefs document that declares the language" },
  { role: "sla", source: "the compiled SLEIGH file that slafile names" },
  { role: "pspec", source: "the processor spec that processorspec names" },
  {
    role: "cspec",
    source: "the compiler spec that the selected compiler names",
  },
] as const;
export type GhidraLanguageDefinitionRole =
  (typeof GHIDRA_LANGUAGE_DEFINITION_FILES)[number]["role"];

const definitionFileSchema = z.strictObject({
  /** Path inside the installation directory, with "/" separators. */
  path: z.string().min(1),
  sha256: digestSchema,
});

/**
 * Version 1 of the catalog entry a caller-selected language resolves to. A
 * community module can change in place under the same language ID, so
 * identity covers these bytes, not only the ID. `address_bits` is the
 * entry's declared size; the import check requires the default address space
 * to match it.
 */
export const ghidraLanguageDefinitionSchema = z.strictObject({
  version: z.literal(1),
  address_bits: z.int().min(1).max(64),
  files: z.strictObject({
    ldefs: definitionFileSchema,
    sla: definitionFileSchema,
    pspec: definitionFileSchema,
    cspec: definitionFileSchema,
  }),
});
export type GhidraLanguageDefinitionCommitment = z.infer<
  typeof ghidraLanguageDefinitionSchema
>;

/** One language definition and the compiler specs it declares. */
export interface GhidraLanguageDefinition {
  readonly id: string;
  readonly compilerSpecIds: readonly string[];
}

// Language definitions are small XML files; refuse anything implausibly large.
const MAX_LDEFS_BYTES = 4 * 1024 * 1024;
// Processor modules ship under Processors; installed extensions may add more.
const LANGUAGE_ROOTS = ["Ghidra/Processors", "Ghidra/Extensions"] as const;

/** Parse the `<language>` elements of one `.ldefs` document. */
export const parseGhidraLanguageDefinitions = (
  text: string,
): readonly GhidraLanguageDefinition[] => {
  const definitions: GhidraLanguageDefinition[] = [];
  const parsed = parseXmlDocument(text, {
    doctype: "allow",
    lineEndings: "normalize",
  });
  if (!parsed.ok) throw parsed.error;
  const document = parsed.value;
  const root = document.documentElement;
  if (root?.tagName !== "language_definitions")
    throw new SyntaxError("Expected Ghidra language_definitions XML root");
  for (const language of Array.from(root.getElementsByTagName("language"))) {
    if (language.parentNode !== root) continue;
    const id = language.getAttribute("id");
    if (id === null) continue;
    const compilerSpecIds: string[] = [];
    for (const compiler of Array.from(
      language.getElementsByTagName("compiler"),
    )) {
      if (compiler.parentNode !== language) continue;
      const compilerId = compiler.getAttribute("id");
      if (compilerId !== null) compilerSpecIds.push(compilerId);
    }
    definitions.push({ id, compilerSpecIds });
  }
  return definitions;
};

const languageDirectories = async (installDir: string): Promise<string[]> => {
  const directories: string[] = [];
  for (const root of LANGUAGE_ROOTS) {
    let modules: string[];
    try {
      modules = await readdir(join(installDir, root));
    } catch (cause: unknown) {
      if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
        continue;
      throw cause;
    }
    for (const module of modules.sort())
      directories.push(join(installDir, root, module, "data", "languages"));
  }
  return directories;
};

/**
 * Parse one definition before its final close; an oversized file declares
 * nothing. The caller's scope owns a descriptor whose close is unconfirmed.
 */
const readLanguageDefinitionFile = (
  path: string,
  resources: ArtifactResourceScope,
  signal: AbortSignal | undefined,
): Promise<readonly GhidraLanguageDefinition[]> =>
  withArtifactRegularFile(
    path,
    resources,
    signal,
    async ({ handle: file }) => {
      const bytes = await readBoundedFileBytes(file, MAX_LDEFS_BYTES, {
        signal,
        cancellationFailure: (reason) =>
          new RegularFileOperationCancelled(reason),
      });
      // The XML byte owner validates encoding and declaration before syntax
      // parsing; a literal U+FFFD cannot diagnose invalid source bytes.
      return bytes === undefined
        ? []
        : parseGhidraLanguageDefinitions(decodeXmlPlistText(bytes));
    },
    "follow",
  );

/**
 * Read every language definition shipped by one Ghidra installation. Admission
 * first retries cleanup the scope retains, so an unconfirmed close blocks reads
 * only until that exact owner releases.
 */
export const readGhidraLanguageCatalog = (
  installDir: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<readonly GhidraLanguageDefinition[]> =>
  resources.run(async () => {
    const definitions: GhidraLanguageDefinition[] = [];
    for (const directory of await languageDirectories(installDir)) {
      let entries: string[];
      try {
        entries = await readdir(directory);
      } catch (cause: unknown) {
        // A module may contain no language directory; inability to read one is not absence.
        if (
          cause instanceof Error &&
          "code" in cause &&
          (cause.code === "ENOENT" || cause.code === "ENOTDIR")
        )
          continue;
        throw cause;
      }
      for (const entry of entries.sort()) {
        if (!entry.endsWith(".ldefs")) continue;
        definitions.push(
          ...(await readLanguageDefinitionFile(
            join(directory, entry),
            resources,
            signal,
          )),
        );
      }
    }
    return definitions;
  });

/**
 * Check a configured import language against the installation before launch,
 * so an unknown ID fails as configuration instead of as a failed import.
 */
export const admitGhidraLanguageOverride = (
  override: GhidraLanguageOverride,
  catalog: readonly GhidraLanguageDefinition[],
  providerVersion: string,
): ConfigurationError | null => {
  const language = catalog.find((value) => value.id === override.languageId);
  if (language === undefined)
    return new ConfigurationError("Invalid REA environment configuration", {
      settings: [
        {
          setting: "REA_GHIDRA_LANGUAGE_ID",
          constraint: `is not a language defined by Ghidra ${providerVersion}`,
        },
      ],
    });
  if (
    override.compilerSpecId !== undefined &&
    !language.compilerSpecIds.includes(override.compilerSpecId)
  )
    return new ConfigurationError("Invalid REA environment configuration", {
      settings: [
        {
          setting: "REA_GHIDRA_COMPILER_SPEC_ID",
          constraint: `must be one of the selected language's compiler specs: ${language.compilerSpecIds.join(", ")}`,
        },
      ],
    });
  return null;
};
