import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse, relative } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import {
  ARM_CPU_ARCH_PROFILE_M,
  ARM_ELF_FLOAT_ABIS,
  ARM_ELF_M_PROFILE_ARCHITECTURES,
} from "../domain/armBuildAttributes.js";
import { ARM_ELF_HEADER } from "../domain/binaryTarget.fixture.js";
import type {
  ArmElfAttributesObservation,
  ArmElfMetadata,
  BinaryTarget,
} from "../domain/binaryTargetTypes.js";
import { ARCHITECTURE_VARIANT_NAMES } from "../domain/architectureVariant.js";
import { ok } from "../domain/result.js";
import { silentLogger } from "../logger.js";
import {
  ghidraPinnedLanguage,
  ghidraProfileLanguageOverride,
  sameGhidraLanguageOverride,
} from "./GhidraAnalysisProfile.js";
import {
  GHIDRA_ARM_ELF_DWARF_PROTOTYPES,
  GHIDRA_ARM_ELF_LANES,
  GHIDRA_ARM_ELF_VERIFIED_FLOAT_ABIS,
  ghidraArmDwarfCallingConvention,
  ghidraArmDwarfCallingConventionFailure,
  ghidraArmDwarfCallingConventionLimitations,
  ghidraArmElfLane,
  ghidraArmLimitations,
  ghidraArmProfileMismatchReason,
  type GhidraDwarfCallingConventionReport,
} from "./GhidraArmProfile.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import type { GhidraHeadlessLauncher } from "./GhidraLauncher.js";
import { GhidraProvider } from "./GhidraProvider.js";
import type { GhidraProviderClientFactory } from "./GhidraProviderClient.js";
import { GHIDRA_SESSION_CAPABILITIES } from "./GhidraSessionValues.js";
import {
  GHIDRA_VARIANT_LANGUAGES,
  GHIDRA_VARIANT_LIMITATIONS,
  ghidraVariantProcessorLabels,
} from "./GhidraRawBinaryLanguage.js";

// Computed at 6565d11d4, before this lane, for an ARM ELF without and with
// REA_GHIDRA_LANGUAGE_ID=ARM:LE:32:Cortex. Targets outside the lane, and a
// caller-selected language, keep these digests and so their snapshots.
const AUTO_DIGEST =
  "386d2baf844aa0a99f1e41184098caff2a52caf228348220ca998610ff7ab4a5";
const CORTEX_OVERRIDE_DIGEST =
  "2fd1db9bc5880f6ecf8e5a04223763a74b34aea337d961edcd888761d6e218ba";

// Abbreviated from Ghidra 12.1.4 Processors/ARM/data/languages/ARM.ldefs.
const ARM_LDEFS = `<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language processor="ARM" endian="little" size="32" variant="v8" id="ARM:LE:32:v8">
    <compiler name="default" spec="ARM.cspec" id="default"/>
  </language>
  <language processor="ARM" endian="little" size="32" variant="Cortex" id="ARM:LE:32:Cortex">
    <compiler name="default" spec="ARM.cspec" id="default"/>
    <compiler name="APCS" spec="ARM_apcs.cspec" id="apcs"/>
  </language>
  <language processor="ARM" endian="little" size="32" variant="v8-m" id="ARM:LE:32:v8-m">
    <compiler name="default" spec="ARM.cspec" id="default"/>
  </language>
</language_definitions>
`;

let installDir = "";
beforeAll(async () => {
  const root =
    process.platform === "win32" ? join(process.cwd(), "build") : tmpdir();
  await mkdir(root, { recursive: true });
  installDir = await mkdtemp(join(root, "rea-ghidra-arm-languages-"));
  // The simulated Linux host needs a POSIX absolute path.
  if (process.platform === "win32")
    installDir = `/${relative(parse(installDir).root, installDir).replaceAll("\\", "/")}`;
  const languages = join(installDir, "Ghidra/Processors/ARM/data/languages");
  await mkdir(languages, { recursive: true });
  await writeFile(join(languages, "ARM.ldefs"), ARM_LDEFS);
});
afterAll(async () => {
  await rm(installDir, { recursive: true, force: true });
});

const ghidra = (
  environment: Record<string, string> = {},
  clientFactory?: GhidraProviderClientFactory,
) => {
  const config = parseConfig({
    GHIDRA_INSTALL_DIR: installDir,
    ...environment,
  });
  if (!config.ok) throw config.error;
  return new GhidraProvider(
    config.value,
    silentLogger,
    {},
    host,
    clientFactory,
  );
};

const M = ARM_CPU_ARCH_PROFILE_M;
const declared = (
  cpuArch: number | null,
  cpuArchProfile: number | null,
  vfpArgs: number | null = null,
): ArmElfAttributesObservation => ({
  status: "declared",
  declarations: { cpuArch, cpuArchProfile, vfpArgs },
});
const armElf = (
  attributes: ArmElfAttributesObservation | undefined,
  header: Partial<ArmElfMetadata> = {},
): BinaryTarget => ({
  path: "/tmp/firmware.elf",
  sha256: "b".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "arm",
  availableArchitectures: ["arm"],
  arm: {
    ...ARM_ELF_HEADER,
    ...header,
    ...(attributes === undefined ? {} : { attributes }),
  },
});
const SOFT = 0x05000200;
const HARD = 0x05000400;
const A = 0x41;

/** The client's binding check, with the language it reads from the profile. */
const mismatch = (
  target: BinaryTarget,
  parameters: Readonly<Record<string, unknown>>,
) =>
  ghidraArmProfileMismatchReason(
    target,
    parameters,
    ghidraProfileLanguageOverride(parameters),
  );

/** Profile parameters without the named ones. */
const omit = (
  parameters: Readonly<Record<string, unknown>>,
  keys: readonly string[],
) =>
  Object.fromEntries(
    Object.entries(parameters).filter(([key]) => !keys.includes(key)),
  );

const profile = async (
  target: BinaryTarget,
  environment: Record<string, string> = {},
) => {
  const resolved = await ghidra(environment).resolveAnalysisProfile(target);
  if (!resolved.ok) throw resolved.error;
  if (resolved.value.profile === null) throw new Error("expected a profile");
  return resolved.value.profile;
};

describe("M-profile ARM ELF lanes", () => {
  it("names one versioned lane per variant", () => {
    // Lane ids are persisted in analysis profiles; renaming one is a new lane.
    expect(GHIDRA_ARM_ELF_LANES).toEqual({
      "armv6-m": "elf32-exec-le-eabi5-armv6-m-pinned-v1",
      "armv7-m": "elf32-exec-le-eabi5-armv7-m-pinned-v1",
      "armv7e-m": "elf32-exec-le-eabi5-armv7e-m-pinned-v1",
      "armv8-m.base": "elf32-exec-le-eabi5-armv8-m.base-pinned-v1",
      "armv8-m.main": "elf32-exec-le-eabi5-armv8-m.main-pinned-v1",
      "armv8.1-m.main": "elf32-exec-le-eabi5-armv8.1-m.main-pinned-v1",
    });
    expect(Object.keys(GHIDRA_ARM_ELF_LANES)).toEqual(
      ARCHITECTURE_VARIANT_NAMES,
    );
  });

  it("verifies only VFP float passing", () => {
    expect(GHIDRA_ARM_ELF_VERIFIED_FLOAT_ABIS).toEqual(["vfp"]);
    for (const abi of GHIDRA_ARM_ELF_VERIFIED_FLOAT_ABIS)
      expect(ARM_ELF_FLOAT_ABIS).toContain(abi);
  });
});

describe.each(ARM_ELF_M_PROFILE_ARCHITECTURES)(
  "Tag_CPU_arch $cpuArch ($label) ELF",
  (row) => {
    const target = armElf(declared(row.cpuArch, M, 1), { flags: HARD });

    it("pins the raw-image decoder and the lane", async () => {
      const language = {
        languageId: GHIDRA_VARIANT_LANGUAGES[row.variant],
        compilerSpecId: "default",
      };
      expect(ghidraArmElfLane(target)).toMatchObject({
        kind: "pinned",
        language,
        lane: GHIDRA_ARM_ELF_LANES[row.variant],
      });
      expect(ghidraPinnedLanguage(target)).toEqual(language);
      const committed = await profile(target);
      expect(committed.parameters).toMatchObject({
        loader: "auto-from-header",
        language_id: language.languageId,
        compiler_spec_id: "default",
        language_selection: "provider-pinned-v1",
        arm_elf: {
          elf_class: 32,
          byte_order: "little",
          type: 2,
          flags: HARD,
          cpu_arch: row.cpuArch,
          cpu_arch_profile: M,
        },
        arm_support_lane: GHIDRA_ARM_ELF_LANES[row.variant],
        processor_labels: ghidraVariantProcessorLabels(row.variant),
      });
      // The pinned profile is a new identity, so earlier snapshots are not reused.
      expect(committed.digest).not.toBe(AUTO_DIGEST);
      expect(
        sameGhidraLanguageOverride(
          ghidraProfileLanguageOverride(committed.parameters),
          ghidraPinnedLanguage(target),
        ),
      ).toBe(true);
      expect(mismatch(target, committed.parameters)).toBe(null);
    });

    it("keeps the lane for a caller-selected language that names the pin", async () => {
      const language = GHIDRA_VARIANT_LANGUAGES[row.variant];
      const pinned = await profile(target);
      for (const [environment, selection] of [
        [
          {
            REA_GHIDRA_LANGUAGE_ID: language,
            REA_GHIDRA_COMPILER_SPEC_ID: "default",
          },
          ["language_selection"],
        ],
        // Without a compiler specification the profile records the language
        // default, which the coordinate digest covers.
        [
          { REA_GHIDRA_LANGUAGE_ID: language },
          [
            "language_selection",
            "compiler_spec_id",
            "function_coordinate_context",
          ],
        ],
      ] as const) {
        const committed = await profile(target, environment);
        // The selection is the caller's; the import and its lane are the pin's.
        expect(committed.parameters.language_selection).toBe("configured-v1");
        expect(omit(committed.parameters, selection)).toEqual(
          omit(pinned.parameters, selection),
        );
        expect(mismatch(target, committed.parameters)).toBe(null);
        expect(ghidraArmLimitations(target, committed.parameters)).toEqual(
          ghidraArmLimitations(target, pinned.parameters),
        );
      }
    });

    it("keeps the profile from before the lane for a different caller-selected language", async () => {
      const language = GHIDRA_VARIANT_LANGUAGES[row.variant];
      const other =
        language === "ARM:LE:32:Cortex" ? "ARM:LE:32:v8-m" : "ARM:LE:32:Cortex";
      const environment = { REA_GHIDRA_LANGUAGE_ID: other };
      const committed = await profile(target, environment);
      // An image outside the lane has the profile from before the lane.
      const outside = await profile(armElf(declared(10, A, 1)), environment);
      expect(committed.digest).toBe(outside.digest);
      if (other === "ARM:LE:32:Cortex")
        expect(committed.digest).toBe(CORTEX_OVERRIDE_DIGEST);
      expect(committed.parameters).not.toHaveProperty("arm_support_lane");
      expect(mismatch(target, committed.parameters)).toBe(null);
      expect(ghidraArmLimitations(target, committed.parameters)).toEqual([
        `ARM ELF: the configured language ${other} replaces ${language}, which REA pins for the ${row.variant} profile that .ARM.attributes declares.`,
      ]);
    });
  },
);

describe("ARM ELF images outside the M-profile lane", () => {
  it.each([
    ["an A-profile declaration", armElf(declared(10, A, 1)), undefined],
    [
      "uninspected attributes of a big-endian image",
      armElf(undefined, { byteOrder: "big" }),
      undefined,
    ],
    [
      "uninspected attributes",
      armElf(undefined),
      "REA did not read .ARM.attributes",
    ],
    [
      "an absent attributes section",
      armElf({ status: "absent" }),
      "the image has no .ARM.attributes section",
    ],
    [
      "an unreadable attributes section",
      armElf({
        status: "unavailable",
        reason: "the image has more than one attributes section",
      }),
      "REA could not read .ARM.attributes: the image has more than one attributes section",
    ],
    [
      "an M-profile architecture without a variant",
      armElf(declared(99, M)),
      "Tag_CPU_arch 99 with profile M has no M-profile variant",
    ],
    [
      "a relocatable M-profile object",
      armElf(declared(13, M), { type: 1 }),
      ".ARM.attributes declares ARMv7E-M (armv7e-m), but the lane covers ET_EXEC images only, and e_type is 1",
    ],
    [
      "an M-profile image with another EABI version",
      armElf(declared(13, M), { flags: 0x04000000 }),
      ".ARM.attributes declares ARMv7E-M (armv7e-m), but the lane covers EABI version 5 images only",
    ],
    [
      "a BE8 M-profile image",
      armElf(declared(13, M), { flags: 0x05800000 }),
      ".ARM.attributes declares ARMv7E-M (armv7e-m), but the lane does not cover EF_ARM_BE8 images",
    ],
    [
      "an unknown profile of a relocatable object",
      armElf({ status: "absent" }, { type: 1 }),
      undefined,
    ],
  ] as const)(
    "keeps the profile from before the lane for %s",
    async (_name, target, reason) => {
      expect(ghidraArmElfLane(target)).toEqual(
        reason === undefined
          ? { kind: "header-selected" }
          : { kind: "header-selected", reason },
      );
      expect(ghidraPinnedLanguage(target)).toBeUndefined();
      const committed = await profile(target);
      expect(committed.digest).toBe(AUTO_DIGEST);
      expect(mismatch(target, committed.parameters)).toBe(null);
      expect(ghidraArmLimitations(target, committed.parameters)).toEqual(
        reason === undefined
          ? []
          : [
              `ARM ELF: REA did not select an M-profile decoder because ${reason}. Ghidra selects the language from the ELF header; its default instruction state is ARM, so code that no entry or symbol marks as Thumb decodes in ARM state.`,
            ],
      );
      // A caller-selected language replaces the header selection without a lane note.
      const configured = await profile(target, {
        REA_GHIDRA_LANGUAGE_ID: "ARM:LE:32:Cortex",
      });
      expect(configured.digest).toBe(CORTEX_OVERRIDE_DIGEST);
      expect(ghidraArmLimitations(target, configured.parameters)).toEqual([]);
    },
  );

  it("keeps the profile from before the lane for the pinned language with another compiler specification", async () => {
    const target = armElf(declared(13, M));
    const environment = {
      REA_GHIDRA_LANGUAGE_ID: "ARM:LE:32:Cortex",
      REA_GHIDRA_COMPILER_SPEC_ID: "apcs",
    };
    const committed = await profile(target, environment);
    expect(committed.parameters).not.toHaveProperty("arm_support_lane");
    expect(committed.digest).toBe(
      (await profile(armElf(declared(10, A, 1)), environment)).digest,
    );
    expect(mismatch(target, committed.parameters)).toBe(null);
  });

  it("accepts a caller-selected language that differs from the pin", async () => {
    const target = armElf(declared(13, M));
    const committed = await profile(target, {
      REA_GHIDRA_LANGUAGE_ID: "ARM:LE:32:v8",
      REA_GHIDRA_COMPILER_SPEC_ID: "default",
    });
    expect(committed.parameters).toMatchObject({
      language_id: "ARM:LE:32:v8",
      compiler_spec_id: "default",
      language_selection: "configured-v1",
    });
  });
});

describe("M-profile ARM ELF session limitations", () => {
  const pinned = async (target: BinaryTarget) =>
    ghidraArmLimitations(target, (await profile(target)).parameters);
  const decoder =
    "ARM ELF: .ARM.attributes declares ARMv7E-M (Tag_CPU_arch 13), so REA pins ARM:LE:32:Cortex for the armv7e-m profile instead of Ghidra's header-based selection, whose default instruction state is ARM. The decoder does not refuse instructions that this profile lacks, and floating-point, TrustZone and memory-protection state are not modelled.";
  const labels =
    "Ghidra's processor-defined vector labels are not applied, so only the ELF's own symbols name vector-table slots and handlers. In a stripped image, a handler that only the vector table references can stay without a function; an analysis seed (REA_GHIDRA_SEED_FILE) can name it.";

  it("states nothing about float passing the lane verifies", async () => {
    expect(await pinned(armElf(declared(13, M, 1), { flags: HARD }))).toEqual([
      decoder,
      labels,
    ]);
  });

  it("states the loop flow that the ARMv8.1-M decoder gets wrong", async () => {
    const loops = GHIDRA_VARIANT_LIMITATIONS["armv8.1-m.main"];
    expect(loops).toEqual([expect.stringContaining("WLS and LE")]);
    expect(await pinned(armElf(declared(21, M, 1), { flags: HARD }))).toEqual([
      "ARM ELF: .ARM.attributes declares ARMv8.1-M Mainline (Tag_CPU_arch 21), so REA pins ARM:LE:32:v8-m for the armv8.1-m.main profile instead of Ghidra's header-based selection, whose default instruction state is ARM. The decoder does not refuse instructions that this profile lacks, and floating-point, TrustZone and memory-protection state are not modelled.",
      ...loops,
      labels,
    ]);
  });

  it("names the base standard and the DWARF prototype REA selects for it", async () => {
    expect(await pinned(armElf(declared(13, M), { flags: SOFT }))).toEqual([
      decoder,
      labels,
      "The image declares the base procedure-call standard (soft-float or softfp): floating-point arguments and results pass in r0-r3. REA sets the DWARF analyzer's default calling convention to Ghidra's __stdcall_softfp, so the signatures it imports keep their float and double types in core registers. A float prototype from any other source keeps Ghidra's default ARM prototype, which passes floating-point values in VFP registers.",
    ]);
  });

  it.each([
    [0x05000000, 3, "declares that no floating-point value crosses"],
    [0x05000000, 2, "toolchain-specific floating-point convention"],
    [SOFT | HARD, null, "conventions that disagree"],
    [0x05000000, null, "declares no floating-point calling convention"],
  ] as const)(
    "admits flags %i with Tag_ABI_VFP_args %s with a limitation",
    async (flags, vfpArgs, declaration) => {
      const limitations = await pinned(
        armElf(declared(13, M, vfpArgs), { flags }),
      );
      expect(limitations.slice(0, 2)).toEqual([decoder, labels]);
      expect(limitations[2]).toContain(declaration);
      expect(limitations[2]).toContain(
        "REA has not verified it against Ghidra's default ARM prototype",
      );
    },
  );
});

describe("M-profile ARM ELF session binding", () => {
  it("rejects a committed profile without the lane this target selects", async () => {
    const target = armElf(declared(13, M));
    const outside = await profile(armElf({ status: "absent" }));
    expect(
      mismatch(target, {
        ...outside.parameters,
        language_selection: "provider-pinned-v1",
      }),
    ).toMatch(/M-profile ARM ELF lane/u);
    const committed = await profile(target);
    expect(mismatch(armElf(declared(16, M)), committed.parameters)).toMatch(
      /M-profile ARM ELF lane/u,
    );
    // A caller-selected language that names the pin commits the lane too.
    expect(
      mismatch(target, {
        ...outside.parameters,
        language_id: "ARM:LE:32:Cortex",
        compiler_spec_id: "language-default",
        language_selection: "configured-v1",
      }),
    ).toMatch(/M-profile ARM ELF lane/u);
    // The label policy is bound with the lane.
    const { processor_labels: _labels, ...unlabelled } = committed.parameters;
    expect(mismatch(target, unlabelled)).toMatch(/M-profile ARM ELF lane/u);
  });

  it("imports with the pinned language, without processor labels, and checks it", async () => {
    const captured: Parameters<GhidraProviderClientFactory>[0][] = [];
    const clientFactory: GhidraProviderClientFactory = (options) => {
      captured.push(options);
      return {
        start: () => Promise.reject(new Error("not started")),
        callTool: () => Promise.reject(new Error("not started")),
        close: () => Promise.resolve(ok(null)),
      };
    };
    for (const [target, environment, labels, dwarf] of [
      [armElf(declared(17, M), { flags: SOFT }), {}, false, "__stdcall_softfp"],
      [armElf(declared(17, M, 1), { flags: HARD }), {}, false, undefined],
      [
        armElf(declared(17, M), { flags: SOFT }),
        { REA_GHIDRA_LANGUAGE_ID: "ARM:LE:32:Cortex" },
        undefined,
        undefined,
      ],
      [
        armElf(declared(13, M), { flags: SOFT }),
        { REA_GHIDRA_LANGUAGE_ID: "ARM:LE:32:Cortex" },
        false,
        "__stdcall_softfp",
      ],
    ] as const) {
      const provider = ghidra(environment, clientFactory);
      const resolved = await provider.resolveAnalysisProfile(target);
      if (!resolved.ok || resolved.value.profile === null)
        throw new Error("expected a profile");
      // The deferred client builds its launcher on first use; this fake never starts.
      const client = provider.createClient(target, resolved.value.profile);
      expect((await client.execute("list_procedures", {})).ok).toBe(false);
      await client.close();
      const options = captured.at(-1);
      const launcher = options?.launcher as GhidraHeadlessLauncher;
      const language = environment.REA_GHIDRA_LANGUAGE_ID ?? "ARM:LE:32:v8-m";
      expect(options?.expectedLanguageId).toBe(language);
      expect(launcher.options.languageOverride?.languageId).toBe(language);
      expect(launcher.options.applyProcessorLabels).toBe(labels);
      expect(launcher.options.dwarfCallingConvention).toBe(dwarf);
    }
  });
});

describe("soft-float DWARF prototype", () => {
  it("commits Ghidra's __stdcall_softfp for base-standard images only", async () => {
    const base = await profile(armElf(declared(13, M), { flags: SOFT }));
    const vfp = await profile(armElf(declared(13, M, 1), { flags: HARD }));
    // The prototype is identity: a base-standard profile differs from a VFP one.
    expect(base.parameters.arm_float_prototype).toBe(
      GHIDRA_ARM_ELF_DWARF_PROTOTYPES.base.commitment,
    );
    expect(vfp.parameters).not.toHaveProperty("arm_float_prototype");
    expect(ghidraArmDwarfCallingConvention(base.parameters)).toBe(
      "__stdcall_softfp",
    );
    expect(ghidraArmDwarfCallingConvention(vfp.parameters)).toBeUndefined();
    // A caller-selected language that names the pin keeps the prototype; a
    // different one keeps the pre-lane profile, without it.
    const matching = await profile(armElf(declared(13, M), { flags: SOFT }), {
      REA_GHIDRA_LANGUAGE_ID: "ARM:LE:32:Cortex",
    });
    expect(matching.parameters.arm_float_prototype).toBe(
      GHIDRA_ARM_ELF_DWARF_PROTOTYPES.base.commitment,
    );
    const different = await profile(armElf(declared(13, M), { flags: SOFT }), {
      REA_GHIDRA_LANGUAGE_ID: "ARM:LE:32:v8-m",
    });
    expect(different.parameters).not.toHaveProperty("arm_float_prototype");
  });

  it("binds the committed prototype to the target's float ABI", async () => {
    const soft = armElf(declared(13, M), { flags: SOFT });
    const hard = armElf(declared(13, M, 1), { flags: HARD });
    const base = await profile(soft);
    expect(mismatch(soft, base.parameters)).toBeNull();
    expect(mismatch(hard, base.parameters)).toMatch(/M-profile ARM ELF lane/u);
    const { arm_float_prototype: _prototype, ...withoutPrototype } =
      base.parameters;
    expect(mismatch(soft, withoutPrototype)).toMatch(/M-profile ARM ELF lane/u);
  });

  it.each([
    [undefined, undefined, undefined],
    [
      "__stdcall_softfp",
      { calling_convention: "__stdcall_softfp", status: "applied" },
      undefined,
    ],
    [
      "__stdcall_softfp",
      { calling_convention: "__stdcall_softfp", status: "not_applicable" },
      undefined,
    ],
    [
      "__stdcall_softfp",
      undefined,
      "did not report the committed DWARF calling convention __stdcall_softfp",
    ],
    [
      "__stdcall_softfp",
      { calling_convention: "__stdcall", status: "applied" },
      "did not report the committed DWARF calling convention __stdcall_softfp",
    ],
    [
      undefined,
      { calling_convention: "__stdcall_softfp", status: "applied" },
      "reported a DWARF calling convention that the profile did not commit",
    ],
  ] as const)(
    "checks a committed %s against the reported %j",
    (expected, report, failure) => {
      const reason = ghidraArmDwarfCallingConventionFailure(expected, report);
      if (failure === undefined) expect(reason).toBeUndefined();
      else expect(reason).toContain(failure);
    },
  );

  it("states when a stripped image leaves the prototype without signatures", () => {
    expect(
      ghidraArmDwarfCallingConventionLimitations({
        calling_convention: "__stdcall_softfp",
        status: "not_applicable",
      }),
    ).toEqual([
      "The image carries no DWARF, so no signature uses __stdcall_softfp; Ghidra infers parameters from the registers the code uses.",
    ]);
    expect(
      ghidraArmDwarfCallingConventionLimitations({
        calling_convention: "__stdcall_softfp",
        status: "applied",
      }),
    ).toEqual([]);
    expect(ghidraArmDwarfCallingConventionLimitations(undefined)).toEqual([]);
  });
});

describe("soft-float DWARF prototype handshake", () => {
  const handshake = async (
    value: BinaryTarget,
    reported: GhidraDwarfCallingConventionReport | undefined,
  ) => {
    const counts = { starts: 0, calls: 0, closes: 0 };
    const provider = ghidra({}, () => ({
      start: () => {
        counts.starts += 1;
        return Promise.resolve(
          ok({
            name: "REA Ghidra bridge" as const,
            run_id: "11111111-1111-4111-8111-111111111111",
            profile_digest: "a".repeat(64),
            provider: { id: "ghidra" as const, version: "12.1.4" },
            read_only: false,
            analysis_complete: true,
            analysis_timed_out: false,
            capabilities: [...GHIDRA_SESSION_CAPABILITIES],
            target: {
              name: "firmware.elf",
              language_id: "ARM:LE:32:Cortex",
              compiler_spec_id: "default",
              image_base: "0x8000000",
              default_address_space: "ram",
              sha256: "b".repeat(64),
            },
            ...(reported === undefined
              ? {}
              : { dwarf_calling_convention: reported }),
          }),
        );
      },
      callTool: () => {
        counts.calls += 1;
        return Promise.resolve(ok(null));
      },
      close: () => {
        counts.closes += 1;
        return Promise.resolve(ok(null));
      },
    }));
    const resolved = await provider.resolveAnalysisProfile(value);
    if (!resolved.ok || resolved.value.profile === null)
      throw new Error("expected an ARM profile");
    return {
      counts,
      client: provider.createClient(value, resolved.value.profile),
    };
  };
  const soft = armElf(declared(13, M), { flags: SOFT });
  const hard = armElf(declared(13, M, 1), { flags: HARD });

  it.each([
    ["applied", []],
    [
      "not_applicable",
      [
        "The image carries no DWARF, so no signature uses __stdcall_softfp; Ghidra infers parameters from the registers the code uses.",
      ],
    ],
  ] as const)("states the %s outcome", async (status, outcome) => {
    const { client } = await handshake(soft, {
      calling_convention: "__stdcall_softfp",
      status,
    });
    const health = await client.execute("health", {});
    if (!health.ok) throw health.error;
    expect(health.value.limitations).toEqual(
      expect.arrayContaining([
        expect.stringContaining("Ghidra's __stdcall_softfp"),
        ...outcome,
      ]),
    );
    if (outcome.length === 0)
      expect(health.value.limitations.join(" ")).not.toContain(
        "carries no DWARF",
      );
    await client.close();
  });

  it.each([
    // Checked before the first analysis call, not only by health.
    [
      "a base-standard session without a report",
      soft,
      undefined,
      "list_procedures",
    ],
    [
      "a report from a session that committed none",
      hard,
      { calling_convention: "__stdcall_softfp", status: "applied" },
      "health",
    ],
  ] as const)("rejects %s", async (_reason, value, reported, operation) => {
    const { counts, client } = await handshake(value, reported);
    const failed = await client.execute(operation, {});
    expect(failed.ok).toBe(false);
    if (!failed.ok) expect(failed.error._tag).toBe("ProviderAdapterError");
    expect(counts).toEqual({ starts: 1, calls: 0, closes: 1 });
  });
});
