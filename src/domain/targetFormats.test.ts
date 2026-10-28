import { describe, expect, expectTypeOf, it } from "vitest";
import type { z } from "zod";

import { analysisSnapshotSchema } from "./analysisSnapshot.js";
import type { BinaryTarget } from "./binaryTargetTypes.js";
import { evidenceSchema } from "./evidence.js";
import { liveBinaryTargetSummarySchema } from "./liveBinaryTargetSummary.js";
import {
  ENTRY_POINT_ROWS,
  inPublishedOrder,
  TARGET_FORMATS,
  type TargetFormatOfKind,
} from "./targetFormats.js";

// Executable members carry per-format metadata, so they stay hand-written;
// these checks fail compilation when a row and its member disagree.
expectTypeOf<BinaryTarget["format"]>().toEqualTypeOf<TargetFormatOfKind>();
expectTypeOf<
  Extract<BinaryTarget, { readonly kind: "executable" }>["format"]
>().toEqualTypeOf<TargetFormatOfKind<"executable">>();
expectTypeOf<
  Extract<BinaryTarget, { readonly entryPoint: string }>["format"]
>().toEqualTypeOf<(typeof ENTRY_POINT_ROWS)[number]["id"]>();

type FormatVariant = { readonly shape: { readonly format: z.ZodType } };
const discriminatorValues = (variants: readonly FormatVariant[]) =>
  variants.flatMap(({ shape: { format } }) =>
    "options" in format
      ? (format.options as readonly string[])
      : [...(format as z.ZodLiteral<string>).values],
  );

describe("target formats", () => {
  it("names each format once", () => {
    const ids = TARGET_FORMATS.map((row) => row.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("gives every derived union exactly one variant per owned format", () => {
    const opened = TARGET_FORMATS.flatMap((row) =>
      "target" in row ? [row.id] : [],
    );
    const live = discriminatorValues(liveBinaryTargetSummarySchema.options);
    const snapshot = discriminatorValues(
      analysisSnapshotSchema.shape.target.options,
    );
    const subject = discriminatorValues(
      evidenceSchema.shape.subject.unwrap().options,
    );
    expect(live.toSorted()).toEqual(opened.toSorted());
    expect(snapshot.toSorted()).toEqual(opened.toSorted());
    expect(subject.toSorted()).toEqual(
      TARGET_FORMATS.map((row) => row.id).toSorted(),
    );
  });

  it("keeps a published order and appends later members in table order", () => {
    expect(inPublishedOrder(["a", "b", "c", "d"], ["c", "a"])).toEqual([
      "c",
      "a",
      "b",
      "d",
    ]);
    // A pinned id that is no longer a member does not reappear.
    expect(inPublishedOrder<string>(["a", "b"], ["c", "b"])).toEqual([
      "b",
      "a",
    ]);
  });
});
