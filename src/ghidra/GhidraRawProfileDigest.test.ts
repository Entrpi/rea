import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import type {
  BinaryTarget,
  FamilyRawBinaryTarget,
  RawBinaryLoad,
} from "../domain/binaryTargetTypes.js";
import {
  ARCHITECTURE_VARIANT_NAMES,
  type ArchitectureVariant,
} from "../domain/architectureVariant.js";
import {
  admittedRawLoad,
  vectorTableWords,
} from "../domain/rawBinary.fixture.js";
import { GHIDRA_VARIANT_LANGUAGES } from "./GhidraRawBinaryLanguage.js";
import { silentLogger } from "../logger.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import { GhidraProvider } from "./GhidraProvider.js";

// Digests commit to the current shared policy, including the instruction
// status, load-image relocation-symbol, procedure search, byte-search and
// bit-field base-type and inventory-search revisions that prevent reuse of snapshots with earlier
// results. On embedded-integration they also include Change 2's
// no_return_repair revision, so they differ from main's.
const RAW_DIGESTS = {
  "6502": "63514828258d47178388803493a409ecd23a9326d53d354247035ac5a212d4c2",
  "x86-disabled-analyzer":
    "a97063fbf3af30bfde7cb725ea2de6551d652b92c1d05d8d29f24182aa9d98b2",
} as const;

// Computed by upstream main at 71f680d7c, which has neither a separate base nor
// a variant, and recomputed on embedded-integration at main 240f08d40, where Change 2's
// no_return_repair revision changes every Ghidra profile. A raw load whose base
// is its caller-selected entry keeps these profile digests, so it stays
// reusable wherever this branch's raw sessions and snapshots are.
const LEGACY_RAW_DIGESTS = [
  [
    "x86",
    "0x1000",
    "1d1c0b9afbbb8f338efacfdd031b51998413b2e990adaf3ffe142fa7547ee70b",
  ],
  [
    "x86_64",
    "0x401000",
    "8f37181664135b535d285b2af3952e5810302a16cc1995a6ba096fddff3d0211",
  ],
  [
    "arm",
    "0x8000000",
    "d89fb24dbb2061e28463e7616883e6f1b06c4768c47bd8a141f43a9cc366eb13",
  ],
  [
    "arm64",
    "0x80000",
    "9c047c819423ddc9c04be9d086d3bd5685b6fc5c1a35678fd185be1cf0b5f35c",
  ],
  [
    "m68k",
    "0x1000",
    "cc9d98375432e4e79d430e69eb3641876ffb8b536a600f774f012e40ecf9be6b",
  ],
] as const;

const configFor = (environment: NodeJS.ProcessEnv) => {
  const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra", ...environment });
  if (!parsed.ok) throw parsed.error;
  return parsed.value;
};

const raw = (
  architecture: FamilyRawBinaryTarget["architecture"],
  entryPoint: string,
): BinaryTarget => ({
  path: "/tmp/raw.bin",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "raw-binary",
  architecture,
  availableArchitectures: [architecture],
  rawLoad: {
    baseAddress: entryPoint,
    entryPoint,
    entrySource: { kind: "caller" },
  },
});

describe("raw-binary analysis profile digest", () => {
  it("commits the 6502 raw profile to the current shared policy", async () => {
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
      load_image_observations:
        "source-mappings-entry-context-relocation-symbol-v3",
      instruction_status: "unlisted-and-containing-code-data-v3",
      inventory_search_projection: "provider-inventory-facts-v1",
      value_flow_effect_scope: "pcode-load-store-explicit-v1",
      byte_search_boundary: "contiguous-eligible-initialized-blocks-v1",
      byte_search_coverage: "separate-loaded-overlays-v1",
      data_type_observations: "bit-field-base-and-lookup-v1",
      instruction_references:
        "exact-address-incoming-without-synthetic-entry-v3",
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
      inventory_search_projection: "provider-inventory-facts-v1",
      value_flow_effect_scope: "pcode-load-store-explicit-v1",
      byte_search_coverage: "separate-loaded-overlays-v1",
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

describe("M-profile raw-binary analysis profile", () => {
  const ghidra = () =>
    new GhidraProvider(configFor({}), silentLogger, {}, host);
  const profile = async (rawLoad: RawBinaryLoad) => {
    const resolved = await ghidra().resolveAnalysisProfile({
      path: "/tmp/raw.bin",
      sha256: "a".repeat(64),
      kind: "executable",
      format: "raw-binary",
      architecture: "arm",
      availableArchitectures: ["arm"],
      rawLoad,
    });
    if (!resolved.ok) throw resolved.error;
    if (resolved.value.profile === null) throw new Error("expected a profile");
    return resolved.value.profile;
  };
  const reset = (
    variant: ArchitectureVariant,
    selection: { baseAddress?: string; vectorTableAddress?: string } = {},
  ) =>
    admittedRawLoad(
      {
        architecture: "arm",
        architectureVariant: variant,
        entryPoint: undefined,
        baseAddress: "0x08000000",
        ...selection,
        fileBytes: 0x200,
      },
      vectorTableWords(0x20005000, 0x080001c5),
    );

  it("keeps the legacy ARM digest for a load admitted without a variant", async () => {
    const legacy = await profile(
      admittedRawLoad({
        architecture: "arm",
        entryPoint: "0x08000000",
        fileBytes: 4,
      }),
    );
    expect(legacy.digest).toBe(
      LEGACY_RAW_DIGESTS.find(([family]) => family === "arm")?.[2],
    );
    expect(legacy.parameters).not.toHaveProperty("raw_load");
  });

  it.each(ARCHITECTURE_VARIANT_NAMES)(
    "commits the %s decoder, Thumb entry context and raw_load",
    async (variant) => {
      const committed = await profile(reset(variant));
      expect(committed.parameters).toMatchObject({
        language_id: GHIDRA_VARIANT_LANGUAGES[variant],
        compiler_spec_id: "default",
        load_image_evidence: "independent-raw-segments-v1",
        entry_context: "thumb-tmode-1-before-analysis-v1",
        processor_labels: "not-applied-v1",
        raw_load: {
          version: 1,
          base_address: "0x8000000",
          architecture_variant: variant,
          vector_table_address: "0x8000000",
          entries: [
            {
              address: "0x80001c4",
              isa_mode: "thumb",
              role: "reset",
              basis: "vector-table",
            },
          ],
        },
      });
      // raw_load holds the base and entry; flat copies would only repeat it.
      expect(committed.parameters).not.toHaveProperty("entry_point");
      expect(committed.parameters).not.toHaveProperty("base_address");
    },
  );

  it("keeps the digest across spellings and provenance only", async () => {
    const digest = (await profile(reset("armv7-m"))).digest;
    // Pinned so a change to raw_load semantics must bump its version.
    expect(digest).toBe(
      "26698e6310c352d8a6e3abdcde24dd006f2809e02463a1ca7ef6572194edd177",
    );
    expect(
      (await profile(reset("armv7-m", { baseAddress: "0x8000000" }))).digest,
    ).toBe(digest);
    expect(
      (await profile(reset("armv7-m", { vectorTableAddress: "0x08000000" })))
        .digest,
    ).toBe(digest);
  });

  it("gives every entry of one image one coordinate context", async () => {
    const derived = await profile(reset("armv7-m"));
    const named = (entryPoint: string) =>
      profile(
        admittedRawLoad({
          architecture: "arm",
          architectureVariant: "armv7-m",
          baseAddress: "0x8000000",
          entryPoint,
          fileBytes: 0x200,
        }),
      );
    // Session identity covers the entry and its basis; coordinates do not.
    for (const other of [await named("0x80001c4"), await named("0x8000100")]) {
      expect(other.digest).not.toBe(derived.digest);
      expect(other.parameters.function_coordinate_context).toEqual(
        derived.parameters.function_coordinate_context,
      );
    }
  });

  it("separates base, variant and vector table", async () => {
    const base = await profile(reset("armv7-m"));
    const coordinates = (committed: typeof base) =>
      committed.parameters.function_coordinate_context;
    const movedBase = await profile(
      admittedRawLoad(
        {
          architecture: "arm",
          architectureVariant: "armv7-m",
          entryPoint: undefined,
          baseAddress: "0x07ffff00",
          fileBytes: 0x400,
        },
        vectorTableWords(0x20005000, 0x080001c5),
      ),
    );
    const v8m = await profile(reset("armv8-m.main"));
    // Same base and decoder: separate sessions, comparable coordinates.
    const sameCoordinates = await Promise.all([
      profile(reset("armv7e-m")),
      profile(reset("armv7-m", { vectorTableAddress: "0x08000100" })),
    ]);
    for (const other of [movedBase, v8m, ...sameCoordinates])
      expect(other.digest).not.toBe(base.digest);
    for (const other of sameCoordinates)
      expect(coordinates(other)).toEqual(coordinates(base));
    expect(coordinates(movedBase)).not.toEqual(coordinates(base));
    expect(coordinates(v8m)).not.toEqual(coordinates(base));
  });
});
