import { describe, expect, it } from "vitest";

import {
  RAW_ARCHITECTURE_VARIANT_NAMES,
  RAW_ARCHITECTURE_VARIANTS,
  RAW_ENTRY_ISA_MODES,
  rawArchitectureVariantRow,
  rawArchitectureVariantSchema,
} from "./rawArchitectureVariant.js";
import { nativeSegmentsLoadImageSchema } from "./native/nativeLoadImage.js";
import {
  binaryArchitectureSchema,
  rawBinarySelectionError,
} from "./rawBinary.js";

describe.each(RAW_ARCHITECTURE_VARIANT_NAMES)(
  "architecture variant %s",
  (name) => {
    const row = RAW_ARCHITECTURE_VARIANTS[name];

    it("names a raw-binary family and a known entry instruction set", () => {
      expect(binaryArchitectureSchema.options).toContain(row.architecture);
      expect(RAW_ENTRY_ISA_MODES).toContain(row.isaMode);
      expect(rawArchitectureVariantRow(name)).toEqual({ name, ...row });
    });

    it.each(binaryArchitectureSchema.options)(
      "pairs only with its own family, not %s otherwise",
      (architecture) => {
        expect(
          rawBinarySelectionError({
            format: "raw-binary",
            architecture,
            entryPoint: "0x8000000",
            architectureVariant: name,
          }),
        ).toEqual(
          architecture === row.architecture
            ? undefined
            : {
                field: "architecture_variant",
                message: `architecture_variant ${name} requires architecture ${row.architecture}`,
              },
        );
      },
    );

    it("lets the entry be omitted only together with a base", () => {
      const selection = {
        format: "raw-binary",
        architecture: row.architecture,
        architectureVariant: name,
      } as const;
      expect(
        rawBinarySelectionError({ ...selection, baseAddress: "0x8000000" }),
      ).toBeUndefined();
      expect(rawBinarySelectionError(selection)).toMatchObject({
        field: "entry_point",
      });
    });
  },
);

describe("architecture variant vocabulary", () => {
  // armv8.1m.main is the LLVM triple's spelling of armv8.1-m.main.
  it.each(["cortex-m", "ARMv7-M", "armv7m", "armv8-m", "armv8.1m.main", ""])(
    "accepts no spelling outside the table: %j",
    (spelling) => {
      expect(rawArchitectureVariantSchema.safeParse(spelling).success).toBe(
        false,
      );
      expect(rawArchitectureVariantRow(spelling)).toBeUndefined();
    },
  );
});

describe("persisted architecture variant names", () => {
  // Saved segments Evidence and snapshots carry these names. Retiring one from
  // the input table must not make that Evidence unreadable.
  it.each([
    "armv6-m",
    "armv7-m",
    "armv7e-m",
    "armv8-m.base",
    "armv8-m.main",
    "armv8.1-m.main",
  ])("keeps %s readable in segments Evidence", (name) => {
    expect(
      nativeSegmentsLoadImageSchema.shape.architecture_variant.safeParse(name)
        .success,
    ).toBe(true);
  });
});
