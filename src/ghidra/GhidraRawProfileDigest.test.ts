import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import { GhidraProvider } from "./GhidraProvider.js";

// Digests were computed by the unmodified upstream resolver (3ae7daa10,
// raw branch inline) and must not change when the binary-loader policy is shared.
const RAW_DIGESTS = {
  "6502": "adbec31711f31471f9cdbdbb2fc743a0ce6b46c9be5568bf90a3f51ef46e376d",
  "x86-disabled-analyzer":
    "493a02888eca575be286b5a96041af8007444586854edb974d6a0c12fd2768c4",
} as const;

// Computed at d6f88becd. A raw load whose base is its caller-selected entry
// keeps these profile digests, so its sessions and snapshots stay reusable.
const LEGACY_RAW_DIGESTS = [
  [
    "x86",
    "0x1000",
    "6e18972704299f8f78c4465502e6c386e52227ef840f11acefbccafde57debca",
  ],
  [
    "x86_64",
    "0x401000",
    "6f2e097fcc748e85165d9acc7bb80e879ce6aed3592b06a603ed14957779c102",
  ],
  [
    "arm",
    "0x8000000",
    "c83436441786074ecde2eb776201e6546311affca43bf8905af7b79c8d387733",
  ],
  [
    "arm64",
    "0x80000",
    "b99f37f9b495c8c4b1479836365cc99868c18959f4d06e3edeb0ba00f95e650d",
  ],
  [
    "m68k",
    "0x1000",
    "3383ab9585908ed99835034bf9f6536fd72dfeeba014cdd965203f8173d8a171",
  ],
] as const;

const configFor = (environment: NodeJS.ProcessEnv) => {
  const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra", ...environment });
  if (!parsed.ok) throw parsed.error;
  return parsed.value;
};

const raw = (
  architecture: Extract<BinaryTarget, { format: "raw-binary" }>["architecture"],
  entryPoint: string,
): BinaryTarget =>
  ({
    path: "/tmp/raw.bin",
    sha256: "a".repeat(64),
    kind: "executable",
    format: "raw-binary",
    architecture,
    availableArchitectures: [architecture],
    entryPoint,
    entryPointSource: entryPoint,
  }) as unknown as BinaryTarget;

describe("raw-binary analysis profile digest", () => {
  it("keeps the 6502 raw profile digest from before the shared policy refactor", async () => {
    const ghidra = new GhidraProvider(configFor({}), silentLogger, {}, host);
    const resolved = await ghidra.resolveAnalysisProfile(raw("6502", "0x8001"));
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile?.digest).toBe(RAW_DIGESTS["6502"]);
    expect(resolved.value.profile?.parameters).toMatchObject({
      target_format: "raw-binary",
      loader: "BinaryLoader",
      language_id: "6502:LE:16:default",
      language_selection: "caller-supplied-v1",
      load_image_evidence: "independent-raw-mapping-context-v4",
      analyzer_preset: "ghidra-default",
    });
  });

  it("keeps the disabled-analyzer raw digest and its analysis options", async () => {
    const ghidra = new GhidraProvider(
      configFor({
        REA_GHIDRA_DISABLED_ANALYZERS: "Aggressive Instruction Finder",
      }),
      silentLogger,
      {},
      host,
    );
    const resolved = await ghidra.resolveAnalysisProfile(raw("x86", "0x1000"));
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile?.digest).toBe(
      RAW_DIGESTS["x86-disabled-analyzer"],
    );
    expect(resolved.value.profile?.parameters).toMatchObject({
      analysis_options: {
        disabled_analyzers: ["Aggressive Instruction Finder"],
      },
    });
  });

  it.each(LEGACY_RAW_DIGESTS)(
    "keeps the %s raw profile digest at entry %s",
    async (architecture, entryPoint, digest) => {
      const ghidra = new GhidraProvider(configFor({}), silentLogger, {}, host);
      const resolved = await ghidra.resolveAnalysisProfile(
        raw(architecture, entryPoint),
      );
      if (!resolved.ok) throw resolved.error;
      expect(resolved.value.profile?.parameters).toMatchObject({
        entry_point: entryPoint,
      });
      expect(resolved.value.profile?.digest).toBe(digest);
    },
  );
});
