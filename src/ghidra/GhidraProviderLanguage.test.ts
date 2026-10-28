import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { parseConfig } from "../config/parseConfig.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { functionCoordinateContextsEqual } from "../domain/native/functionCoordinateContext.js";
import { providerLanguageRawTarget } from "../domain/rawBinary.fixture.js";
import { silentLogger } from "../logger.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import { resolveGhidraLanguageDefinition } from "./GhidraLanguageCatalog.js";
import { GhidraProvider } from "./GhidraProvider.js";

// A community-style module: one .ldefs with several entries over shared files.
const COMMUNITY_LDEFS = `<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language processor="F5SH" endian="little" size="32" variant="community"
            version="1.0" slafile="f5.sla" processorspec="f5.pspec"
            id="F5SH:LE:32:community">
    <description>Simulated community module</description>
    <compiler name="default" spec="f5.cspec" id="default"/>
  </language>
  <language processor="F5W" endian="big" size="16" variant="default"
            version="1.0" slafile="f5.sla" processorspec="f5.pspec"
            id="F5W:BE:16:default">
    <description>A 16-bit language</description>
    <compiler name="default" spec="f5.cspec" id="default"/>
  </language>
  <language processor="F5H" endian="little" size="32" variant="default"
            version="1.0" slafile="f5.sla" processorspec="f5.pspec"
            hidden="true" id="F5H:LE:32:default">
    <description>Hidden outside development mode</description>
    <compiler name="default" spec="f5.cspec" id="default"/>
  </language>
  <language processor="F5N" endian="little" size="32" variant="default"
            version="1.0" slafile="uncompiled.sla" processorspec="f5.pspec"
            id="F5N:LE:32:default">
    <description>Sources only</description>
    <compiler name="default" spec="f5.cspec" id="default"/>
  </language>
  <language processor="F5U" endian="little" size="32" variant="default"
            version="1.0" slafile="../f5.sla" processorspec="f5.pspec"
            id="F5U:LE:32:default">
    <description>Outside its directory</description>
    <compiler name="default" spec="f5.cspec" id="default"/>
  </language>
  <language processor="F5Z" endian="little" size="128" variant="default"
            version="1.0" slafile="f5.sla" processorspec="f5.pspec"
            id="F5Z:LE:128:default">
    <description>Wider than any address REA admits</description>
    <compiler name="default" spec="f5.cspec" id="default"/>
  </language>
  <language processor="F5D" endian="little" size="32" variant="default"
            version="1.0" slafile="f5.sla" processorspec="f5.pspec"
            id="F5D:LE:32:default">
    <description>Defined twice</description>
    <compiler name="default" spec="f5.cspec" id="default"/>
  </language>
</language_definitions>
`;
const DUPLICATE_LDEFS = `<language_definitions>
  <language processor="F5D" endian="little" size="32" variant="default"
            version="1.0" slafile="f5.sla" processorspec="f5.pspec"
            id="F5D:LE:32:default">
    <description>Defined twice</description>
    <compiler name="default" spec="f5.cspec" id="default"/>
  </language>
</language_definitions>
`;
const FILES = {
  "f5.sla": "sla\u0004 compiled sleigh",
  "f5.pspec": "<processor_spec/>",
  "f5.cspec": "<compiler_spec/>",
} as const;

const sha256 = (text: string): string =>
  createHash("sha256").update(text).digest("hex");
const MODULE = "Ghidra/Processors/F5/data/languages";

let installDir = "";
beforeAll(async () => {
  installDir = await mkdtemp(join(tmpdir(), "rea-ghidra-provider-language-"));
  await mkdir(join(installDir, MODULE), { recursive: true });
  await writeFile(join(installDir, MODULE, "f5.ldefs"), COMMUNITY_LDEFS);
  for (const [name, text] of Object.entries(FILES))
    await writeFile(join(installDir, MODULE, name), text);
  const duplicate = join(installDir, "Ghidra/Extensions/F5D/data/languages");
  await mkdir(duplicate, { recursive: true });
  await writeFile(join(duplicate, "dup.ldefs"), DUPLICATE_LDEFS);
});
afterAll(async () => {
  if (installDir !== "") await rm(installDir, { recursive: true, force: true });
});

const resolve = (languageId: string, compilerSpecId = "default") =>
  resolveGhidraLanguageDefinition(
    installDir,
    { languageId, compilerSpecId },
    "12.1.4",
    new ArtifactResourceScope(),
  );

describe("Ghidra provider language catalog resolution", () => {
  it("digests the .ldefs document and the files its entry names", async () => {
    expect(await resolve("F5SH:LE:32:community")).toEqual({
      ok: true,
      value: {
        version: 1,
        address_bits: 32,
        files: {
          ldefs: {
            path: `${MODULE}/f5.ldefs`,
            sha256: sha256(COMMUNITY_LDEFS),
          },
          sla: { path: `${MODULE}/f5.sla`, sha256: sha256(FILES["f5.sla"]) },
          pspec: {
            path: `${MODULE}/f5.pspec`,
            sha256: sha256(FILES["f5.pspec"]),
          },
          cspec: {
            path: `${MODULE}/f5.cspec`,
            sha256: sha256(FILES["f5.cspec"]),
          },
        },
      },
    });
  });

  it.each([
    [
      "Absent:LE:32:default",
      "default",
      "Absent:LE:32:default is not a language defined by Ghidra 12.1.4",
    ],
    [
      "F5H:LE:32:default",
      "default",
      "F5H:LE:32:default is not a language defined by Ghidra 12.1.4",
    ],
    [
      "F5D:LE:32:default",
      "default",
      `F5D:LE:32:default is defined by more than one .ldefs entry (${MODULE}/f5.ldefs, Ghidra/Extensions/F5D/data/languages/dup.ldefs); REA cannot tell which one Ghidra loads`,
    ],
    [
      "F5SH:LE:32:community",
      "gcc",
      "compiler_spec_id must be one of F5SH:LE:32:community's compiler specs: default",
    ],
    [
      "F5N:LE:32:default",
      "default",
      "F5N:LE:32:default has no compiled SLEIGH file uncompiled.sla. Ghidra would compile it into its installation when it loads the language, and REA does not change the installation; compile the module first",
    ],
    [
      "F5U:LE:32:default",
      "default",
      'F5U:LE:32:default names its sla file "../f5.sla"; REA resolves definition files only beside the .ldefs file',
    ],
    [
      "F5Z:LE:128:default",
      "default",
      "F5Z:LE:128:default declares no address size from 1 to 64 bits in its .ldefs entry",
    ],
  ])("refuses %s with %s", async (languageId, compilerSpecId, reason) => {
    expect(await resolve(languageId, compilerSpecId)).toEqual({
      ok: false,
      error: reason,
    });
  });
});

describe("Ghidra provider language profile", () => {
  const provider = (environment: Record<string, string> = {}) => {
    const parsed = parseConfig({
      GHIDRA_INSTALL_DIR: installDir,
      ...environment,
    });
    if (!parsed.ok) throw parsed.error;
    return new GhidraProvider(parsed.value, silentLogger, {}, host);
  };
  const target = (
    languageId: string,
    selection: { entryPoint: string; baseAddress?: string; fileBytes?: number },
  ) =>
    providerLanguageRawTarget(
      { provider: "ghidra", languageId, compilerSpecId: "default" },
      selection,
    );
  const profile = async (subject: ReturnType<typeof target>) => {
    const resolved = await provider().resolveAnalysisProfile(subject);
    if (!resolved.ok) throw resolved.error;
    if (resolved.value.profile === null) throw new Error("expected a profile");
    return resolved.value.profile;
  };

  it("commits the caller's language, its definition and no family", async () => {
    const committed = await profile(
      target("F5SH:LE:32:community", {
        baseAddress: "0x8c000000",
        entryPoint: "0x8c000010",
      }),
    );
    expect(committed.parameters).toMatchObject({
      target_format: "raw-binary",
      architecture: null,
      available_architectures: [],
      load_image_evidence: "independent-raw-segments-v1",
      loader: "BinaryLoader",
      language_id: "F5SH:LE:32:community",
      compiler_spec_id: "default",
      language_selection: "caller-provider-language-v1",
      language_definition: {
        version: 1,
        address_bits: 32,
        files: { sla: { sha256: sha256(FILES["f5.sla"]) } },
      },
      entry_point: "0x8c000010",
      base_address: "0x8c000000",
      raw_load: {
        version: 1,
        base_address: "0x8c000000",
        provider_language: {
          provider: "ghidra",
          language_id: "F5SH:LE:32:community",
          compiler_spec_id: "default",
        },
        entries: [{ address: "0x8c000010", role: "entry", basis: "caller" }],
      },
      processor_labels: "not-applied-v1",
      entry_seed: "external-entry-and-function-before-analysis-v1",
    });
    expect(committed.parameters).not.toHaveProperty("entry_context");
  });

  it.each([
    [{ entryPoint: "0xffff", fileBytes: 1 }, undefined],
    [
      { entryPoint: "0xfff0", fileBytes: 0x11 },
      "raw-binary mapping from 0xfff0 to 0x10000 must fit in the 16-bit address size that F5W:BE:16:default declares",
    ],
    [
      { baseAddress: "0x10000", entryPoint: "0x10000" },
      "raw-binary mapping from 0x10000 to 0x1001f must fit in the 16-bit address size that F5W:BE:16:default declares",
    ],
  ])(
    "checks the image against the declared address size: %j",
    async (selection, reason) => {
      const resolved = await provider().resolveAnalysisProfile(
        target("F5W:BE:16:default", selection),
      );
      if (reason === undefined) {
        expect(resolved.ok).toBe(true);
        return;
      }
      if (resolved.ok) throw new Error("expected a refusal");
      expect(projectAnalysisError(resolved.error)).toMatchObject({
        code: "invalid_request",
        details: { reason, constraint: "load_selection_rejected" },
      });
    },
  );

  it("refuses an unknown language as a load selection the caller can correct", async () => {
    const resolved = await provider().resolveAnalysisProfile(
      target("Absent:LE:32:default", { entryPoint: "0x0" }),
    );
    if (resolved.ok) throw new Error("expected a refusal");
    expect(projectAnalysisError(resolved.error)).toMatchObject({
      code: "invalid_request",
      details: {
        reason:
          "Absent:LE:32:default is not a language defined by Ghidra 12.1.4",
        constraint: "load_selection_rejected",
      },
    });
  });

  it("still refuses REA_GHIDRA_LANGUAGE_ID for a raw target", async () => {
    const resolved = await provider({
      REA_GHIDRA_LANGUAGE_ID: "F5SH:LE:32:community",
    }).resolveAnalysisProfile(
      target("F5SH:LE:32:community", { entryPoint: "0x0" }),
    );
    expect(resolved.ok).toBe(false);
  });

  it.each(["f5.ldefs", "f5.sla", "f5.pspec", "f5.cspec"])(
    "gives a module changed in place under the same ID a new identity: %s",
    async (name) => {
      const subject = target("F5SH:LE:32:community", { entryPoint: "0x0" });
      const before = await profile(subject);
      expect((await profile(subject)).digest).toBe(before.digest);
      const path = join(installDir, MODULE, name);
      const original =
        name === "f5.ldefs"
          ? COMMUNITY_LDEFS
          : FILES[name as keyof typeof FILES];
      await writeFile(
        path,
        name === "f5.ldefs"
          ? original.replace("Simulated", "Updated")
          : `${original}\n`,
      );
      try {
        const after = await profile(subject);
        expect(after.digest).not.toBe(before.digest);
        expect(functionCoordinateContextsEqual(before, after)).toBe(false);
      } finally {
        await writeFile(path, original);
      }
      expect((await profile(subject)).digest).toBe(before.digest);
    },
  );
});
