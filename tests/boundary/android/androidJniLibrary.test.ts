import { expect, it } from "vitest";
import {
  decodeJniModifiedUtf8,
  inspectAndroidJniLibrary,
} from "../../../src/native/android/AndroidJniLibrary.js";
import { androidJniLibraryFactsSchema } from "../../../src/domain/android/androidJniLibraryFacts.js";
import { jniElfFixture } from "../../fixtures/android/jniElf.js";

it.each([
  [64, 183, "rela"],
  [64, 62, "rela"],
  [32, 40, "rel"],
  [32, 3, "rel"],
  [64, 183, "relr"],
  [64, 62, "relr"],
  [32, 40, "relr"],
  [32, 3, "relr"],
] as const)(
  "decodes %s-bit machine %s %s static tables with complete slot provenance",
  async (bits, machine, encoding) => {
    const fixture = jniElfFixture({ bits, machine, encoding });
    const original = Buffer.from(fixture.bytes);
    const result = await inspectAndroidJniLibrary(fixture.bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error.message);
    expect(androidJniLibraryFactsSchema.safeParse(result.value).success).toBe(
      true,
    );
    expect(result.value.exports.map((row) => row.name)).toEqual([
      "JNI_OnLoad",
      "Java_fixture_Owner_exported",
    ]);
    expect(result.value.coverage).toMatchObject({
      status: "complete",
      relocations_status: "complete",
      tables_status: "complete",
    });
    expect(result.value.tables.map((table) => table.section_name)).toEqual([
      ".data",
      ".data.rel.ro",
    ]);
    expect(
      result.value.tables
        .flatMap((table) => table.entries)
        .map((row) => [
          row.name,
          row.descriptor,
          row.function_address,
          row.code_address,
          row.function_file_offset,
        ]),
    ).toEqual([
      [
        "call_猫",
        "()V",
        machine === 40 ? "0x10101" : "0x10100",
        "0x10100",
        0x100,
      ],
      [
        "overload",
        "(I)I",
        machine === 40 ? "0x10111" : "0x10110",
        "0x10110",
        0x110,
      ],
      [
        "𐐀",
        "([Ljava/lang/String;)J",
        machine === 40 ? "0x10121" : "0x10120",
        "0x10120",
        0x120,
      ],
    ]);
    const first = result.value.tables[0]?.entries[0];
    expect(
      first?.slots.map((slot) => [
        slot.role,
        slot.address,
        slot.file_offset,
        slot.value,
        slot.relocation?.encoding,
      ]),
    ).toEqual([
      ["name", "0x10500", 0x500, "0x10400", encoding],
      [
        "signature",
        `0x${(0x10500 + fixture.word).toString(16)}`,
        0x500 + fixture.word,
        "0x10420",
        encoding,
      ],
      [
        "function",
        `0x${(0x10500 + 2 * fixture.word).toString(16)}`,
        0x500 + fixture.word * 2,
        machine === 40 ? "0x10101" : "0x10100",
        encoding,
      ],
    ]);
    expect(fixture.bytes.equals(original)).toBe(true);
  },
);

it("does not limit the writable scan to named or read-only relocation data", async () => {
  const result = await inspectAndroidJniLibrary(
    jniElfFixture({ unnamedData: true }).bytes,
  );
  expect(result.ok && result.value.tables[0]).toMatchObject({
    section_index: 3,
    section_name: "",
    table_address: "0x10500",
  });
});

it.each([32, 64] as const)(
  "keeps later valid entries after a %s-bit unresolved function relocation",
  async (bits) => {
    const result = await inspectAndroidJniLibrary(
      jniElfFixture({ bits, symbolicFirstFunction: true }).bytes,
    );
    if (!result.ok) throw new Error(result.error.message);
    expect(result.value.coverage).toMatchObject({
      status: "partial",
      relocations_status: "partial",
      tables_status: "partial",
    });
    expect(
      result.value.tables
        .flatMap((table) => table.entries)
        .map((row) => row.name),
    ).toEqual(["overload", "𐐀"]);
  },
);

it("keeps exports and explicit unknown table coverage for Android packed relocations", async () => {
  const result = await inspectAndroidJniLibrary(
    jniElfFixture({ packed: true }).bytes,
  );
  if (!result.ok) throw new Error(result.error.message);
  expect(result.value.exports).toHaveLength(2);
  expect(result.value.tables).toEqual([]);
  expect(result.value.coverage).toMatchObject({
    exports_status: "complete",
    relocations_status: "unknown",
    tables_status: "unknown",
  });
  expect(result.value.unknowns.join("\n")).toContain("APS2");
});

it("rejects a leading RELR bitmap rather than interpreting it as an address", async () => {
  const { bytes } = jniElfFixture({ encoding: "relr" });
  bytes.writeBigUInt64LE(7n, 0x800);
  expect(await inspectAndroidJniLibrary(bytes)).toMatchObject({
    ok: false,
    error: {
      kind: "malformed",
      message: "RELR bitmap has no preceding address",
    },
  });
});

it("preserves later candidates after malformed Modified UTF-8 and a malformed JNI descriptor", async () => {
  const { bytes } = jniElfFixture();
  bytes.set([0xf0, 0x90, 0x90, 0x80, 0], 0x400);
  bytes.write("(Lbad.name;)V\0", 0x460, "utf8");
  const result = await inspectAndroidJniLibrary(bytes);
  if (!result.ok) throw new Error(result.error.message);
  expect(
    result.value.tables
      .flatMap((table) => table.entries)
      .map((row) => row.name),
  ).toEqual(["𐐀"]);
});

it.each([
  [[], ""],
  [[0xc0, 0x80], "\0"],
  [[0xed, 0xa0, 0x81, 0xed, 0xb0, 0x80], "𐐀"],
  [[0xed, 0xa0, 0x80], "\ud800"],
  [[0], undefined],
  [[0xc0, 0x81], undefined],
  [[0xc1, 0xbf], undefined],
  [[0xe0, 0x80, 0x80], undefined],
  [[0xf0, 0x90, 0x90, 0x80], undefined],
  [[0xe7, 0x8c], undefined],
  [[0x80], undefined],
] as const)("decodes exact Modified UTF-8 bytes %o", (bytes, value) => {
  expect(decodeJniModifiedUtf8(Uint8Array.from(bytes))).toBe(value);
});

it("returns explicit cancellation before decoding and never runs a target", async () => {
  const control = new AbortController();
  control.abort(new Error("selected cancellation"));
  expect(
    await inspectAndroidJniLibrary(jniElfFixture().bytes, {
      signal: control.signal,
    }),
  ).toMatchObject({ ok: false, error: { kind: "cancelled" } });
});

it.each([32, 64] as const)(
  "preserves an observed %s-bit big-endian ELF rather than assigning an Android ABI",
  async (bits) => {
    const result = await inspectAndroidJniLibrary(
      jniElfFixture({ bits, little: false }).bytes,
    );
    if (!result.ok) throw new Error(result.error.message);
    expect(result.value.byte_order).toBe("big");
    expect(result.value.tables.flatMap((table) => table.entries)).toHaveLength(
      3,
    );
    expect(androidJniLibraryFactsSchema.safeParse(result.value).success).toBe(
      true,
    );
  },
);

it("cooperatively preserves cancellation after the export packet", async () => {
  const controller = new AbortController();
  const operation = inspectAndroidJniLibrary(jniElfFixture().bytes, {
    signal: controller.signal,
  });
  controller.abort(new Error("cancel at the first scheduled yield"));
  expect(await operation).toMatchObject({
    ok: false,
    error: { kind: "cancelled" },
  });
});

const appendRelative = (
  bytes: Buffer,
  destination: bigint,
  value: bigint,
  kind = 1027,
) => {
  const at = 0x800 + 9 * 24;
  bytes.writeBigUInt64LE(destination, at);
  bytes.writeBigUInt64LE(BigInt(kind), at + 8);
  bytes.writeBigUInt64LE(value, at + 16);
  bytes.writeBigUInt64LE(10n * 24n, 0xc18);
};

it("keeps conflicting and partially overwritten pointers unknown while retaining later entries", async () => {
  for (const conflict of [
    "different-relative-value",
    "partial-symbolic-write",
  ] as const) {
    const { bytes } = jniElfFixture();
    appendRelative(
      bytes,
      conflict === "different-relative-value" ? 0x10510n : 0x10511n,
      0x10110n,
      conflict === "different-relative-value" ? 1027 : 258,
    );
    const result = await inspectAndroidJniLibrary(bytes);
    if (!result.ok) throw new Error(result.error.message);
    expect(
      result.value.tables
        .flatMap((table) => table.entries)
        .map((entry) => entry.name),
    ).toEqual(["overload", "𐐀"]);
    expect(result.value.coverage.relocations_status).toBe("partial");
  }
});

it("does not recover a method name from stored bytes changed by loader relocations", async () => {
  const { bytes } = jniElfFixture();
  appendRelative(bytes, 0x10400n, 0n);
  const result = await inspectAndroidJniLibrary(bytes);
  if (!result.ok) throw new Error(result.error.message);
  expect(
    result.value.tables
      .flatMap((table) => table.entries)
      .map((entry) => entry.name),
  ).toEqual(["overload", "𐐀"]);
  expect(result.value.coverage.tables_status).toBe("partial");
  expect(result.value.unknowns.join("\n")).toContain(
    "candidate strings overlap relocation writes",
  );
});

it("reports unavailable section load mappings without hiding later writable sections", async () => {
  const { bytes } = jniElfFixture();
  bytes.writeBigUInt64LE(0x900000n, 0x1400 + 3 * 64 + 16);
  const result = await inspectAndroidJniLibrary(bytes);
  if (!result.ok) throw new Error(result.error.message);
  expect(
    result.value.tables
      .flatMap((table) => table.entries)
      .map((entry) => entry.name),
  ).toEqual(["𐐀"]);
  expect(result.value.coverage.tables_status).toBe("partial");
  expect(result.value.unknowns.join("\n")).toContain(
    "not file-backed in PT_LOAD",
  );
});

it.each(["rel", "rela", "relr"] as const)(
  "accepts empty %s tables without demanding a mapping for an empty span",
  async (encoding) => {
    const { bytes } = jniElfFixture({ encoding });
    bytes.writeBigUInt64LE(0n, 0xc08);
    bytes.writeBigUInt64LE(0n, 0xc18);
    const result = await inspectAndroidJniLibrary(bytes);
    if (!result.ok) throw new Error(result.error.message);
    expect(result.value.coverage.relocations_status).toBe("complete");
  },
);
