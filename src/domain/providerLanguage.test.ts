import { describe, expect, it } from "vitest";

import { analysisSnapshotSchema } from "./analysisSnapshot.js";
import { liveBinaryTargetSummarySchema } from "./liveBinaryTargetSummary.js";
import { nativeSegmentsLoadImageSchema } from "./native/nativeLoadImage.js";
import {
  providerLanguageIdentity,
  providerLanguageProviderIssue,
  type ProviderLanguageSelection,
} from "./providerLanguage.js";
import {
  PROVIDER_LANGUAGE_PAIRING,
  rawBinarySelectionError,
} from "./rawBinary.js";
import { executableFormatHintSchema } from "./dosCom.js";

const analysisSnapshotTargetSchema = analysisSnapshotSchema.shape.target;

const sh4: ProviderLanguageSelection = {
  provider: "ghidra",
  languageId: "SuperH4:LE:32:default",
  compilerSpecId: "default",
};

describe("provider language selection", () => {
  it.each([
    [undefined, undefined, undefined],
    [undefined, "hopper", undefined],
    [sh4, "ghidra", undefined],
    [
      sh4,
      undefined,
      "provider_language names ghidra; provider_id must select ghidra explicitly, not automatic selection",
    ],
    [
      sh4,
      "auto",
      "provider_language names ghidra; provider_id must select ghidra explicitly, not automatic selection",
    ],
    [
      sh4,
      "hopper",
      "provider_language names ghidra; provider_id must select ghidra, not hopper",
    ],
  ] as const)(
    "applies only with its own provider selected: %j with %s",
    (selection, provider, issue) => {
      expect(providerLanguageProviderIssue(selection, provider)).toBe(issue);
    },
  );

  it("persists the caller's fields unchanged", () => {
    expect(providerLanguageIdentity(sh4)).toEqual({
      provider: "ghidra",
      language_id: "SuperH4:LE:32:default",
      compiler_spec_id: "default",
    });
  });
});

describe("provider language pairing", () => {
  const admissible = {
    format: "raw-binary",
    providerLanguage: sh4,
    entryPoint: "0x8c000010",
  } as const;
  // One input for each rule, in the order the rules apply.
  const breaking = {
    architecture: { architecture: "arm" },
    architecture_variant: { architectureVariant: "armv7-m" },
    vector_table_address: { vectorTableAddress: "0x8c000000" },
    entry_point: { entryPoint: undefined },
  } as const satisfies Record<
    (typeof PROVIDER_LANGUAGE_PAIRING)[number]["field"],
    object
  >;

  it("admits an entry, with or without a separate base", () => {
    expect(rawBinarySelectionError(admissible)).toBeUndefined();
    expect(
      rawBinarySelectionError({ ...admissible, baseAddress: "0x8c000000" }),
    ).toBeUndefined();
  });

  it.each(PROVIDER_LANGUAGE_PAIRING)(
    "names $field when it refuses the selection",
    (rule) => {
      expect(
        rawBinarySelectionError({ ...admissible, ...breaking[rule.field] }),
      ).toEqual({ field: rule.field, message: rule.message });
    },
  );

  it("applies the rules in table order", () => {
    expect(
      rawBinarySelectionError({
        format: "raw-binary",
        providerLanguage: sh4,
        architecture: "arm",
        architectureVariant: "armv7-m",
      }),
    ).toEqual({
      field: "architecture",
      message: PROVIDER_LANGUAGE_PAIRING[0].message,
    });
  });

  it.each(
    [undefined, ...executableFormatHintSchema.options].filter(
      (format) => format !== "raw-binary",
    ),
  )("refuses a provider language with format %s", (format) => {
    expect(
      rawBinarySelectionError({
        ...(format === undefined ? {} : { format }),
        providerLanguage: sh4,
      }),
    ).toEqual({
      field: "provider_language",
      message: "provider_language applies only with format=raw-binary",
    });
  });
});

describe("provider language persisted shapes", () => {
  const providerLanguage = providerLanguageIdentity(sh4);
  const rawLoad = {
    version: 1,
    base_address: "0x8c000000",
    provider_language: providerLanguage,
    entries: [{ address: "0x8c000010", role: "entry", basis: "caller" }],
  } as const;
  const sha256 = "a".repeat(64);

  it("reports a null architecture only beside a provider language", () => {
    const summary = {
      path: "/fixture/firmware.bin",
      sha256,
      kind: "executable",
      format: "raw-binary",
      entry_point: "0x8c000010",
      base_address: "0x8c000000",
    } as const;
    expect(
      liveBinaryTargetSummarySchema.safeParse({
        ...summary,
        architecture: null,
        provider_language: { ...providerLanguage, verification: "unverified" },
      }).success,
    ).toBe(true);
    expect(
      liveBinaryTargetSummarySchema.safeParse({
        ...summary,
        architecture: null,
      }).success,
    ).toBe(false);
    expect(
      liveBinaryTargetSummarySchema.safeParse({
        ...summary,
        architecture: "arm",
        provider_language: { ...providerLanguage, verification: "unverified" },
      }).success,
    ).toBe(false);
  });

  it("identifies a snapshot target with a null architecture only by its provider language", () => {
    const target = {
      sha256,
      kind: "executable",
      format: "raw-binary",
      entry_point: "0x8c000010",
    } as const;
    expect(
      analysisSnapshotTargetSchema.safeParse({
        ...target,
        architecture: null,
        raw_load: rawLoad,
      }).success,
    ).toBe(true);
    expect(
      analysisSnapshotTargetSchema.safeParse({
        ...target,
        architecture: null,
        raw_load: { ...rawLoad, provider_language: undefined },
      }).success,
    ).toBe(false);
    expect(
      analysisSnapshotTargetSchema.safeParse({
        ...target,
        architecture: "arm",
        raw_load: rawLoad,
      }).success,
    ).toBe(false);
  });

  it("keeps the provider language opaque in raw load identity", () => {
    expect(
      analysisSnapshotTargetSchema.safeParse({
        sha256,
        kind: "executable",
        format: "raw-binary",
        architecture: null,
        entry_point: "0x8c000010",
        raw_load: {
          ...rawLoad,
          provider_language: { ...providerLanguage, extra: true },
        },
      }).success,
    ).toBe(false);
  });

  it("lets a segments load image name no architecture", () => {
    const parsed = nativeSegmentsLoadImageSchema.shape.architecture;
    expect(parsed.safeParse(null).success).toBe(true);
    expect(parsed.safeParse("arm").success).toBe(true);
  });
});
