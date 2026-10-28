import { createHash } from "node:crypto";
import { readdir } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import { z } from "zod";
import { digestSchema } from "../domain/digests.js";
import { err, ok, type Result } from "../domain/result.js";
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

/** One language definition as its `.ldefs` entry declares it. */
export interface GhidraLanguageDefinition {
  readonly id: string;
  /** Declared size in bits; null when absent or not a decimal integer. */
  readonly size: number | null;
  /** File names the entry gives its compiled SLEIGH and processor spec. */
  readonly slaFile: string | null;
  readonly processorSpec: string | null;
  readonly compilers: readonly {
    readonly id: string;
    readonly spec: string | null;
  }[];
}

/** A catalog entry with the `.ldefs` document that declares it. */
export interface GhidraCatalogLanguage extends GhidraLanguageDefinition {
  readonly ldefsPath: string;
  /** SHA-256 of the `.ldefs` bytes this entry was parsed from. */
  readonly ldefsSha256: string;
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
    // Ghidra skips hidden languages outside development mode.
    if (language.getAttribute("hidden") === "true") continue;
    const compilers: { id: string; spec: string | null }[] = [];
    for (const compiler of Array.from(
      language.getElementsByTagName("compiler"),
    )) {
      if (compiler.parentNode !== language) continue;
      const compilerId = compiler.getAttribute("id");
      if (compilerId !== null)
        compilers.push({ id: compilerId, spec: compiler.getAttribute("spec") });
    }
    const size = language.getAttribute("size");
    definitions.push({
      id,
      size: size !== null && /^[0-9]{1,4}$/u.test(size) ? Number(size) : null,
      slaFile: language.getAttribute("slafile"),
      processorSpec: language.getAttribute("processorspec"),
      compilers,
    });
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
): Promise<readonly GhidraCatalogLanguage[]> =>
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
      if (bytes === undefined) return [];
      const ldefsSha256 = sha256(bytes);
      return parseGhidraLanguageDefinitions(decodeXmlPlistText(bytes)).map(
        (definition) => ({ ...definition, ldefsPath: path, ldefsSha256 }),
      );
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
): Promise<readonly GhidraCatalogLanguage[]> =>
  resources.run(async () => {
    const definitions: GhidraCatalogLanguage[] = [];
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
  const compilerSpecIds = language.compilers.map((compiler) => compiler.id);
  if (
    override.compilerSpecId !== undefined &&
    !compilerSpecIds.includes(override.compilerSpecId)
  )
    return new ConfigurationError("Invalid REA environment configuration", {
      settings: [
        {
          setting: "REA_GHIDRA_COMPILER_SPEC_ID",
          constraint: `must be one of the selected language's compiler specs: ${compilerSpecIds.join(", ")}`,
        },
      ],
    });
  return null;
};

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

// Ghidra 12.1.4 refuses a compiled SLEIGH file over 16 MiB (SlaFormat).
const MAX_SLA_BYTES = 16 * 1024 * 1024;

/** Ghidra resolves these names beside the `.ldefs` file; REA resolves nothing else. */
const isSiblingFileName = (name: string): boolean =>
  name !== "" && name !== "." && name !== ".." && !/[/\\]/u.test(name);

const digestFile = (
  path: string,
  maxBytes: number,
  resources: ArtifactResourceScope,
  signal: AbortSignal | undefined,
): Promise<string | undefined> =>
  withArtifactRegularFile(
    path,
    resources,
    signal,
    async ({ handle: file }) => {
      const bytes = await readBoundedFileBytes(file, maxBytes, {
        signal,
        cancellationFailure: (reason) =>
          new RegularFileOperationCancelled(reason),
      });
      return bytes === undefined ? undefined : sha256(bytes);
    },
    "follow",
  );

/**
 * Resolve a caller-selected language to the one catalog entry that defines it
 * and digest the files Ghidra loads for it: the `.ldefs` document, and the
 * `.sla`, `.pspec` and `.cspec` it names. A refusal names what the caller can
 * correct; a failed read throws. The digests are of the bytes read here, so
 * the raw prepare script compares them with the files Ghidra loaded.
 */
export const resolveGhidraLanguageDefinition = (
  installDir: string,
  selection: { readonly languageId: string; readonly compilerSpecId: string },
  providerVersion: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<Result<GhidraLanguageDefinitionCommitment, string>> =>
  resources.run(async () => {
    const { languageId, compilerSpecId } = selection;
    const catalog = await readGhidraLanguageCatalog(
      installDir,
      resources,
      signal,
    );
    const installPath = (path: string): string =>
      relative(installDir, path).split(sep).join("/");
    const matches = catalog.filter((language) => language.id === languageId);
    const language = matches[0];
    if (language === undefined)
      return err(
        `${languageId} is not a language defined by Ghidra ${providerVersion}`,
      );
    if (matches.length > 1)
      return err(
        `${languageId} is defined by more than one .ldefs entry (${matches
          .map((match) => installPath(match.ldefsPath))
          .join(", ")}); REA cannot tell which one Ghidra loads`,
      );
    const compiler = language.compilers.find(
      (candidate) => candidate.id === compilerSpecId,
    );
    if (compiler === undefined)
      return err(
        `compiler_spec_id must be one of ${languageId}'s compiler specs: ${language.compilers
          .map((candidate) => candidate.id)
          .join(", ")}`,
      );
    if (language.size === null || language.size < 1 || language.size > 64)
      return err(
        `${languageId} declares no address size from 1 to 64 bits in its .ldefs entry`,
      );
    const directory = dirname(language.ldefsPath);
    const siblings = new Set(await readdir(directory));
    const named = [
      ["sla", language.slaFile, MAX_SLA_BYTES],
      ["pspec", language.processorSpec, MAX_LDEFS_BYTES],
      ["cspec", compiler.spec, MAX_LDEFS_BYTES],
    ] as const;
    const files: Partial<
      Record<
        GhidraLanguageDefinitionRole,
        { readonly path: string; readonly sha256: string }
      >
    > = {
      ldefs: {
        path: installPath(language.ldefsPath),
        sha256: language.ldefsSha256,
      },
    };
    for (const [role, name, maxBytes] of named) {
      if (name === null || !isSiblingFileName(name))
        return err(
          `${languageId} names its ${role} file ${JSON.stringify(name)}; REA resolves definition files only beside the .ldefs file`,
        );
      if (!siblings.has(name))
        return err(
          role === "sla"
            ? `${languageId} has no compiled SLEIGH file ${name}. Ghidra would compile it into its installation when it loads the language, and REA does not change the installation; compile the module first`
            : `${languageId} names ${role} file ${name}, which is not beside its .ldefs file`,
        );
      const path = join(directory, name);
      const digest = await digestFile(path, maxBytes, resources, signal);
      if (digest === undefined)
        return err(
          `${languageId}'s ${role} file ${name} is larger than ${String(maxBytes)} bytes`,
        );
      files[role] = { path: installPath(path), sha256: digest };
    }
    return ok(
      ghidraLanguageDefinitionSchema.parse({
        version: 1,
        address_bits: language.size,
        files,
      }),
    );
  });

/** Content digests of a committed definition; paths do not move coordinates. */
export const ghidraLanguageDefinitionDigests = (
  definition: GhidraLanguageDefinitionCommitment,
): Readonly<Record<GhidraLanguageDefinitionRole, string>> => ({
  ldefs: definition.files.ldefs.sha256,
  sla: definition.files.sla.sha256,
  pspec: definition.files.pspec.sha256,
  cspec: definition.files.cspec.sha256,
});
