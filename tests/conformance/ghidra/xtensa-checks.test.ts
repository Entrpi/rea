import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseBinaryTarget } from "../../../src/application/BinaryTargetResolver.js";
import { ghidraXtensaUnsupportedReason } from "../../../src/ghidra/GhidraXtensaProfile.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  assertXtensaCFixturePseudocode,
  assertXtensaCall0CFixturePseudocode,
  assertXtensaCall0FixtureInstructions,
  assertXtensaCall0FixturePseudocode,
  assertXtensaFixtureInstructions,
  assertXtensaFixturePseudocode,
  parseXtensaReadelf,
  xtensaCall0KeptValue,
  xtensaCall0RomKeptValue,
} from "./xtensa-checks.mjs";
import {
  mutateXtensaFixture,
  writeXtensaCall0Fixture,
  writeXtensaFixture,
  XTENSA_CALL0_C_FIXTURE_VALUES,
  XTENSA_CALL0_FIXTURE_VALUES,
  XTENSA_FIXTURE_SYMBOLS,
} from "./xtensa-fixture.mjs";

// GNU readelf 2.43.1 (Espressif esp-14.2.0_20251107) output for the
// source-owned fixture. This tests the reader boundary, not Ghidra.
const readelf = `ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Tensilica Xtensa Processor
  Version:                           0x1
  Entry point address:               0x40080004
  Start of program headers:          52 (bytes into file)
  Start of section headers:          4344 (bytes into file)
  Flags:                             0x300
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         1
  Size of section headers:           40 (bytes)
  Number of section headers:         6
  Section header string table index: 5

Symbol table '.symtab' contains 4 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 40080000     4 OBJECT  GLOBAL DEFAULT    1 rea_xtensa_literal
     2: 40080004    13 FUNC    GLOBAL DEFAULT    1 rea_xtensa_entry
     3: 40080014     8 FUNC    GLOBAL DEFAULT    1 rea_xtensa_leaf

Displaying notes found in: .xtensa.info
  Owner                Data size \tDescription
  Xtensa_Info          0x00000020\tNT_VERSION (version)\t   description data: 55 53 45 5f 41 42 53 4f 4c 55 54 45 5f 4c 49 54 45 52 41 4c 53 3d 30 0a 41 42 49 3d 30 0a 00 00
`;
const names = Object.keys(XTENSA_FIXTURE_SYMBOLS);

const instruction = (
  mnemonic: string,
  bytes: string,
  flow: { kind: string; direct_destinations: string[] },
  references: { target_address: string }[] = [],
) => ({
  status: "decoded",
  architecture: "Xtensa:LE:32:default",
  mnemonic,
  bytes,
  flow,
  references,
});
const decoded = {
  entry: instruction("entry", "364100", {
    kind: "fallthrough",
    direct_destinations: [],
  }),
  l32r: instruction(
    "l32r",
    "a1feff",
    { kind: "fallthrough", direct_destinations: [] },
    [{ target_address: "0x40080000" }],
  ),
  call8: instruction("call8", "a50000", {
    kind: "call",
    direct_destinations: ["0x40080014"],
  }),
  retw: instruction("retw.n", "1df0", {
    kind: "return",
    direct_destinations: [],
  }),
};
const addresses = { leaf: "0x40080014", literal: "0x40080000" };

// Ghidra 12.1.4 decompiled the fixtures this way in verify:ghidra:xtensa.
const ENTRY =
  "\nundefined4 rea_xtensa_entry(void)\n\n{\n  undefined4 uVar1;\n  \n  uVar1 = rea_xtensa_leaf(0x12345678);\n  return uVar1;\n}\n\n";
const LEAF =
  "\nint rea_xtensa_leaf(int param_1)\n\n{\n  return param_1 + 7;\n}\n\n";
const C_ENTRY =
  "\n/* WARNING: Unknown calling convention -- yet parameter storage is locked */\n\nuint rea_xtensa_c_entry(void)\n\n{\n  uint uVar1;\n  \n  memw();\n  uVar1 = rea_xtensa_c_scale(rea_xtensa_c_global,5);\n  return uVar1;\n}\n\n";
const C_SCALE =
  "\nuint rea_xtensa_c_scale(uint value,uint factor)\n\n{\n  return value * factor + 0x1234567;\n}\n\n";
const VALUES = { literal: 0x12345678, addend: 7 };
const C_VALUES = {
  global: "rea_xtensa_c_global",
  factor: 5,
  constant: 0x1234567,
};
const entryWith = (body: string) =>
  `undefined4 rea_xtensa_entry(void)\n{\n  ${body}\n}`;
const leafWith = (body: string) =>
  `int rea_xtensa_leaf(int param_1)\n{\n  ${body}\n}`;

describe("Xtensa lane oracle and assertions", () => {
  it("reads the header, symbols and windowed declaration GNU readelf reports", () => {
    expect(parseXtensaReadelf(readelf, names)).toEqual({
      xtensa: {
        elfClass: 32,
        byteOrder: "little",
        type: 2,
        flags: 0x300,
        abi: { status: "declared", abi: "windowed" },
      },
      symbols: {
        rea_xtensa_literal: "0x40080000",
        rea_xtensa_entry: "0x40080004",
        rea_xtensa_leaf: "0x40080014",
      },
      descriptor: "USE_ABSOLUTE_LITERALS=0\nABI=0\n",
    });
    expect(() =>
      parseXtensaReadelf(readelf.replace(/Displaying notes[^]*$/u, ""), names),
    ).toThrow(/Xtensa_Info note/u);
    // ABI=1 is call0; binutils defines no other value.
    const call0 = readelf.replace("41 42 49 3d 30 0a", "41 42 49 3d 31 0a");
    expect(parseXtensaReadelf(call0, names).xtensa.abi).toEqual({
      status: "declared",
      abi: "call0",
    });
    expect(() =>
      parseXtensaReadelf(
        readelf.replace("41 42 49 3d 30 0a", "41 42 49 3d 32 0a"),
        names,
      ),
    ).toThrow(/ABI=2/u);
  });

  it("accepts the fixture's decoded instructions and refuses a wrong call target", () => {
    expect(() =>
      assertXtensaFixtureInstructions(decoded, addresses),
    ).not.toThrow();
    expect(() =>
      assertXtensaFixtureInstructions(
        {
          ...decoded,
          call8: instruction("call8", "a50000", {
            kind: "call",
            direct_destinations: ["0x40080018"],
          }),
        },
        addresses,
      ),
    ).toThrow();
    expect(() =>
      assertXtensaFixtureInstructions(
        { ...decoded, l32r: instruction("l32r", "a1feff", decoded.l32r.flow) },
        addresses,
      ),
    ).toThrow(/no reference to its literal/u);
  });

  it("writes a fixture REA admits, and the mutations the lane refuses", async () => {
    const directory = await createTestTempDirectory("rea-xtensa-fixture-");
    const fixture = await writeXtensaFixture(directory);
    const target = await parseBinaryTarget(fixture.path);
    if (!target.ok) throw target.error;
    expect(target.value).toMatchObject({
      architecture: "xtensa",
      xtensa: {
        elfClass: 32,
        byteOrder: "little",
        type: 2,
        flags: 0x300,
        abi: { status: "declared", abi: "windowed" },
      },
    });
    expect(ghidraXtensaUnsupportedReason(target.value)).toBeNull();
    for (const [index, [change, reason]] of (
      [
        [{ flags: 0x700 }, "(0x400)"],
        [{ flags: 0x301 }, "machine 1"],
        [{ type: 3 }, "shared and position-independent"],
        [{ abi: "2" }, "ABI=2"],
      ] as const
    ).entries()) {
      const path = join(directory, `mutated-${index}.elf`);
      await writeFile(path, mutateXtensaFixture(fixture.bytes, change));
      const mutated = await parseBinaryTarget(path);
      if (!mutated.ok) throw mutated.error;
      expect(ghidraXtensaUnsupportedReason(mutated.value)).toContain(reason);
    }
  });
});

describe("Xtensa lane decompiled dataflow", () => {
  it.each([
    { name: "Ghidra 12.1.4 output", entry: ENTRY, leaf: LEAF },
    {
      name: "a direct return with a cast and a decimal literal",
      entry: entryWith("return (undefined4)rea_xtensa_leaf(305419896);"),
      leaf: leafWith("return 7 + param_1;"),
    },
  ])("accepts the call8 dataflow in $name", ({ entry, leaf }) => {
    expect(() =>
      assertXtensaFixturePseudocode(entry, leaf, VALUES),
    ).not.toThrow();
  });

  it.each([
    {
      name: "the literal returned instead of passed",
      entry: entryWith("rea_xtensa_leaf(0);\n  return 0x12345678;"),
      leaf: LEAF,
      error: /must pass 0x12345678 to rea_xtensa_leaf/u,
    },
    {
      name: "an unmodeled argument register",
      entry: ENTRY.replace("0x12345678", "in_a10"),
      leaf: LEAF,
      error: /must pass 0x12345678 to rea_xtensa_leaf/u,
    },
    {
      name: "the call result discarded",
      entry: entryWith("rea_xtensa_leaf(0x12345678);\n  return 0;"),
      leaf: LEAF,
      error: /must return the rea_xtensa_leaf result/u,
    },
    {
      name: "the call result overwritten",
      entry: ENTRY.replace("return uVar1", "uVar1 = 0;\n  return uVar1"),
      leaf: LEAF,
      error: /must return the rea_xtensa_leaf result/u,
    },
    {
      name: "a leaf that ignores its argument",
      entry: ENTRY,
      leaf: leafWith("return in_a2 + 7;"),
      error: /must return its argument plus 7/u,
    },
  ])("refuses $name", ({ entry, leaf, error }) => {
    expect(() => assertXtensaFixturePseudocode(entry, leaf, VALUES)).toThrow(
      error,
    );
  });

  it.each([
    { name: "Ghidra 12.1.4 output", entry: C_ENTRY, scale: C_SCALE },
    {
      name: "a direct return and reordered operands",
      entry:
        "uint rea_xtensa_c_entry(void)\n{\n  return rea_xtensa_c_scale(rea_xtensa_c_global,5);\n}",
      scale: C_SCALE.replace(
        "value * factor + 0x1234567",
        "0x1234567 + (factor * value)",
      ),
    },
  ])("accepts the C fixture dataflow in $name", ({ entry, scale }) => {
    expect(() =>
      assertXtensaCFixturePseudocode(entry, scale, C_VALUES),
    ).not.toThrow();
  });

  it.each([
    {
      name: "swapped call8 arguments",
      entry: C_ENTRY.replace("rea_xtensa_c_global,5", "5,rea_xtensa_c_global"),
      scale: C_SCALE,
      error: /must pass rea_xtensa_c_global, 0x5 to rea_xtensa_c_scale/u,
    },
    {
      name: "the C call result discarded",
      entry: C_ENTRY.replace(
        "uVar1 = rea_xtensa_c_scale",
        "rea_xtensa_c_scale",
      ).replace("return uVar1", "return 0"),
      scale: C_SCALE,
      error: /must return the rea_xtensa_c_scale result/u,
    },
    {
      name: "the constant without the product",
      entry: C_ENTRY,
      scale: C_SCALE.replace("value * factor + ", ""),
      error: /must return value \* factor \+ 0x1234567/u,
    },
  ])("refuses $name", ({ entry, scale, error }) => {
    expect(() =>
      assertXtensaCFixturePseudocode(entry, scale, C_VALUES),
    ).toThrow(error);
  });
});

// Ghidra 12.1.4 decompiled the call0 fixture this way in verify:ghidra:xtensa,
// and the same bytes declared windowed with the default prototype.
const CALL0_ENTRY =
  "\nint __call0 rea_xtensa_call0_entry(int param_1)\n\n{\n  int iVar1;\n  \n  iVar1 = rea_xtensa_call0_leaf(0x12345678);\n  return iVar1 + param_1 + 5;\n}\n\n";
const WINDOWED_DEFAULT_ENTRY =
  "\nint rea_xtensa_call0_entry(int param_1)\n\n{\n  int iVar1;\n  \n  param_1 = param_1 + 5;\n  iVar1 = rea_xtensa_call0_leaf(0x12345678);\n  return iVar1 + param_1;\n}\n\n";
const CALL0_LEAF =
  "\nint __call0 rea_xtensa_call0_leaf(int param_1)\n\n{\n  return param_1 + 7;\n}\n\n";
// verify:ghidra:xtensa output for xtensa-esp32-elf-gcc 14.2.0 -mabi=call0 -O1 -g.
const CALL0_C_ENTRY =
  "\nuint __call0 rea_xtensa_call0_c_entry(uint value)\n\n{\n  uint uVar1;\n  \n                    /* Unresolved local var: uint kept@[???] */\n  uVar1 = rea_xtensa_call0_c_scale(value ^ 0x5a,5);\n  return uVar1 + (value ^ 0x5a);\n}\n\n";
const CALL0_C_SCALE =
  "\nuint __call0 rea_xtensa_call0_c_scale(uint value,uint factor)\n\n{\n  return factor + 0x1234567 + value;\n}\n\n";
const call0Decoded = {
  l32r: instruction(
    "l32r",
    "21fcff",
    { kind: "fallthrough", direct_destinations: [] },
    [{ target_address: "0x40100000" }],
  ),
  call0: instruction("call0", "c50000", {
    kind: "call",
    direct_destinations: ["0x40100020"],
  }),
  ret: instruction("ret.n", "0df0", {
    kind: "return",
    direct_destinations: [],
  }),
  callx0: instruction("callx0", "c00300", {
    kind: "call",
    direct_destinations: [],
  }),
};
const ROM_CALLER = (body: string) =>
  `int __call0 rea_xtensa_call0_rom_caller(int param_1)\n\n{\n  int iVar1;\n  \n  ${body}\n}\n`;

describe("Xtensa call0 lane fixture and dataflow", () => {
  it("writes a call0 fixture REA admits, which the lane can declare windowed", async () => {
    const directory = await createTestTempDirectory("rea-xtensa-call0-");
    const fixture = await writeXtensaCall0Fixture(directory);
    const target = await parseBinaryTarget(fixture.path);
    if (!target.ok) throw target.error;
    expect(target.value).toMatchObject({
      architecture: "xtensa",
      xtensa: { flags: 0x300, abi: { status: "declared", abi: "call0" } },
    });
    expect(ghidraXtensaUnsupportedReason(target.value)).toBeNull();
    const path = join(directory, "declared-windowed.elf");
    await writeFile(path, mutateXtensaFixture(fixture.bytes, { abi: "0" }));
    const windowed = await parseBinaryTarget(path);
    if (!windowed.ok) throw windowed.error;
    expect(windowed.value).toMatchObject({
      xtensa: { abi: { status: "declared", abi: "windowed" } },
    });
  });

  it("accepts the call0 fixture's decoded instructions", () => {
    const addresses = { leaf: "0x40100020", literal: "0x40100000" };
    expect(() =>
      assertXtensaCall0FixtureInstructions(call0Decoded, addresses),
    ).not.toThrow();
    expect(() =>
      assertXtensaCall0FixtureInstructions(
        {
          ...call0Decoded,
          call0: instruction("call0", "c50000", {
            kind: "call",
            direct_destinations: ["0x40100024"],
          }),
        },
        addresses,
      ),
    ).toThrow();
  });

  it("tells the folded a12 value from the windowed default's spill", () => {
    expect(xtensaCall0KeptValue(CALL0_ENTRY, XTENSA_CALL0_FIXTURE_VALUES)).toBe(
      "folded",
    );
    expect(
      xtensaCall0KeptValue(WINDOWED_DEFAULT_ENTRY, XTENSA_CALL0_FIXTURE_VALUES),
    ).toBe("before-call");
    expect(() =>
      assertXtensaCall0FixturePseudocode(
        CALL0_ENTRY,
        CALL0_LEAF,
        XTENSA_CALL0_FIXTURE_VALUES,
      ),
    ).not.toThrow();
    expect(() =>
      assertXtensaCall0FixturePseudocode(
        WINDOWED_DEFAULT_ENTRY,
        CALL0_LEAF,
        XTENSA_CALL0_FIXTURE_VALUES,
      ),
    ).toThrow(/must keep a12 across call0/u);
  });

  it.each([
    {
      name: "a lost a12 value",
      entry: CALL0_ENTRY.replace("+ param_1 + 5", "+ unaff_a12"),
      error: /plus its argument plus 5:/u,
    },
    {
      name: "the literal not passed",
      entry: CALL0_ENTRY.replace("0x12345678", "in_a2"),
      error: /must pass 0x12345678/u,
    },
  ])("refuses $name", ({ entry, error }) => {
    expect(() =>
      xtensaCall0KeptValue(entry, XTENSA_CALL0_FIXTURE_VALUES),
    ).toThrow(error);
  });

  it("classifies the mask-ROM call, which has no function and keeps the default", () => {
    // Ghidra 12.1.4 decompiled the fixture's ROM caller this way with `__call0`.
    expect(
      xtensaCall0RomKeptValue(
        ROM_CALLER(
          "param_1 = param_1 + 5;\n  iVar1 = (*(code *)&SUB_40002000)();\n  return iVar1 + param_1;",
        ),
        XTENSA_CALL0_FIXTURE_VALUES,
      ),
    ).toBe("before-call");
    expect(
      xtensaCall0RomKeptValue(
        ROM_CALLER(
          "param_1 = param_1 + 5;\n  iVar1 = (*(code *)0x40002000)();\n  return iVar1 + param_1;",
        ),
        XTENSA_CALL0_FIXTURE_VALUES,
      ),
    ).toBe("before-call");
    expect(() =>
      xtensaCall0RomKeptValue(
        ROM_CALLER(
          "param_1 = param_1 + 5;\n  iVar1 = (*(code *)0x140002000)();\n  return iVar1 + param_1;",
        ),
        XTENSA_CALL0_FIXTURE_VALUES,
      ),
    ).toThrow(/must call 0x40002000 once/u);
    expect(
      xtensaCall0RomKeptValue(
        ROM_CALLER(
          "iVar1 = (*(code *)rea_xtensa_call0_rom_address)();\n  return iVar1 + param_1 + 5;",
        ),
        XTENSA_CALL0_FIXTURE_VALUES,
      ),
    ).toBe("folded");
    expect(() =>
      xtensaCall0RomKeptValue(
        ROM_CALLER("iVar1 = (*(code *)0x40002000)();\n  return iVar1;"),
        XTENSA_CALL0_FIXTURE_VALUES,
      ),
    ).toThrow(/plus its argument plus 5:/u);
    expect(() =>
      xtensaCall0RomKeptValue(
        ROM_CALLER("return param_1 + 5;"),
        XTENSA_CALL0_FIXTURE_VALUES,
      ),
    ).toThrow(/must call 0x40002000 once/u);
  });

  it("accepts the compiled call0 fixture and refuses its windowed-default spill", () => {
    expect(() =>
      assertXtensaCall0CFixturePseudocode(
        CALL0_C_ENTRY,
        CALL0_C_SCALE,
        XTENSA_CALL0_C_FIXTURE_VALUES,
      ),
    ).not.toThrow();
    // Ghidra 12.1.4 printed this for the same build with the default prototype.
    const spilled = CALL0_C_ENTRY.replace(
      "uVar1 = rea_xtensa_call0_c_scale(value ^ 0x5a,5);\n  return uVar1 + (value ^ 0x5a);",
      "value_00 = value ^ 0x5a;\n  uVar1 = rea_xtensa_call0_c_scale(value_00,5);\n  return uVar1 + value_00;",
    );
    expect(() =>
      assertXtensaCall0CFixturePseudocode(
        spilled,
        CALL0_C_SCALE,
        XTENSA_CALL0_C_FIXTURE_VALUES,
      ),
    ).toThrow(/must pass value \^ 0x5a and 5/u);
    expect(() =>
      assertXtensaCall0CFixturePseudocode(
        CALL0_C_ENTRY,
        CALL0_C_SCALE.replace("factor + ", ""),
        XTENSA_CALL0_C_FIXTURE_VALUES,
      ),
    ).toThrow(/must return value \+ factor \+ 0x1234567/u);
  });
});
