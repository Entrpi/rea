import { createHash } from "node:crypto";

import type { GhidraCatalogLanguage } from "../../src/ghidra/GhidraLanguageCatalog.js";

/**
 * The catalog entry for one `<language>` element that declares no size, SLEIGH
 * or processor files, read from the definition file at `ldefsPath`.
 */
export const catalogLanguage = (
  id: string,
  ldefsPath: string,
  bytes: Uint8Array | string,
  compilers: GhidraCatalogLanguage["compilers"] = [],
): GhidraCatalogLanguage => ({
  id,
  size: null,
  slaFile: null,
  processorSpec: null,
  compilers,
  ldefsPath,
  ldefsSha256: createHash("sha256").update(bytes).digest("hex"),
});
