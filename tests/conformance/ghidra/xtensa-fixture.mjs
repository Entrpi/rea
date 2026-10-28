import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);

/**
 * Source-owned windowed-ABI code, so the base lane needs no Xtensa compiler.
 * GNU as and objdump from Espressif's esp-14.2.0_20251107 toolchain produced
 * and decoded these bytes once:
 *
 *   0x40080000 78563412  rea_xtensa_literal: .word 0x12345678
 *   0x40080004 364100    rea_xtensa_entry:   entry   a1, 32
 *   0x40080007 a1feff                        l32r    a10, 0x40080000
 *   0x4008000a a50000                        call8   0x40080014
 *   0x4008000d 2d0a                          mov.n   a2, a10
 *   0x4008000f 1df0                          retw.n
 *   0x40080011 000000                        (alignment)
 *   0x40080014 364100    rea_xtensa_leaf:    entry   a1, 32
 *   0x40080017 22c207                        addi    a2, a2, 7
 *   0x4008001a 1df0                          retw.n
 */
export const XTENSA_FIXTURE_TEXT = Buffer.from(
  "78563412364100a1feffa500002d0a1df000000036410022c2071df0",
  "hex",
);
const BASE = 0x40080000;
export const XTENSA_FIXTURE_SYMBOLS = {
  rea_xtensa_literal: { address: BASE, size: 4, type: "OBJECT" },
  rea_xtensa_entry: { address: BASE + 4, size: 13, type: "FUNC" },
  rea_xtensa_leaf: { address: BASE + 0x14, size: 8, type: "FUNC" },
};
/** Instruction addresses the lane inspects, from the annotation above. */
export const XTENSA_FIXTURE_INSTRUCTIONS = {
  entry: BASE + 4,
  l32r: BASE + 7,
  call8: BASE + 0xa,
  retw: BASE + 0xf,
};
/** The literal `l32r` loads and the leaf's addend. */
export const XTENSA_FIXTURE_LITERAL = 0x12345678;
export const XTENSA_FIXTURE_ADDEND = 7;
/** What `../c/xtensa.c` passes through call8 and the constant it loads. */
export const XTENSA_C_FIXTURE_VALUES = {
  global: "rea_xtensa_c_global",
  factor: 5,
  constant: 0x1234567,
};

/**
 * Source-owned call0 code in ESP8266 IRAM. GNU as `--abi-call0` and objdump
 * from Espressif's esp-14.2.0_20251107 toolchain produced and decoded these
 * bytes once. Each caller keeps its argument plus 5 in callee-saved a12
 * across a call: to the leaf, and through a register to 0x40002000, an
 * address outside the image, as ESP8266 code calls mask ROM:
 *
 *   0x40100000 78563412  rea_xtensa_call0_literal: .word 0x12345678
 *   0x40100004 12c1f0    rea_xtensa_call0_entry:   addi    a1, a1, -16
 *   0x40100007 0901                                s32i.n  a0, a1, 0
 *   0x40100009 c911                                s32i.n  a12, a1, 4
 *   0x4010000b 5bc2                                addi.n  a12, a2, 5
 *   0x4010000d 21fcff                              l32r    a2, 0x40100000
 *   0x40100010 c50000                              call0   0x40100020
 *   0x40100013 ca22                                add.n   a2, a2, a12
 *   0x40100015 c811                                l32i.n  a12, a1, 4
 *   0x40100017 0801                                l32i.n  a0, a1, 0
 *   0x40100019 12c110                              addi    a1, a1, 16
 *   0x4010001c 0df0                                ret.n
 *   0x4010001e 0000                                (alignment)
 *   0x40100020 7b22      rea_xtensa_call0_leaf:    addi.n  a2, a2, 7
 *   0x40100022 0df0                                ret.n
 *   0x40100024 00200040  rea_xtensa_call0_rom_address: .word 0x40002000
 *   0x40100028 12c1f0    rea_xtensa_call0_rom_caller:  addi    a1, a1, -16
 *   0x4010002b 0901                                    s32i.n  a0, a1, 0
 *   0x4010002d c911                                    s32i.n  a12, a1, 4
 *   0x4010002f c2c205                                  addi    a12, a2, 5
 *   0x40100032 31fcff                                  l32r    a3, 0x40100024
 *   0x40100035 c00300                                  callx0  a3
 *   0x40100038 ca22                                    add.n   a2, a2, a12
 *   0x4010003a c811                                    l32i.n  a12, a1, 4
 *   0x4010003c 0801                                    l32i.n  a0, a1, 0
 *   0x4010003e 12c110                                  addi    a1, a1, 16
 *   0x40100041 0df0                                    ret.n
 */
export const XTENSA_CALL0_FIXTURE_TEXT = Buffer.from(
  "7856341212c1f00901c9115bc221fcffc50000ca22c811080112c1100df000007b220df0" +
    "0020004012c1f00901c911c2c20531fcffc00300ca22c811080112c1100df0",
  "hex",
);
const CALL0_BASE = 0x40100000;
export const XTENSA_CALL0_FIXTURE_SYMBOLS = {
  rea_xtensa_call0_literal: { address: CALL0_BASE, size: 4, type: "OBJECT" },
  rea_xtensa_call0_entry: { address: CALL0_BASE + 4, size: 26, type: "FUNC" },
  rea_xtensa_call0_leaf: { address: CALL0_BASE + 0x20, size: 4, type: "FUNC" },
  rea_xtensa_call0_rom_address: {
    address: CALL0_BASE + 0x24,
    size: 4,
    type: "OBJECT",
  },
  rea_xtensa_call0_rom_caller: {
    address: CALL0_BASE + 0x28,
    size: 27,
    type: "FUNC",
  },
};
/** Instruction addresses the lane inspects, from the annotation above. */
export const XTENSA_CALL0_FIXTURE_INSTRUCTIONS = {
  l32r: CALL0_BASE + 0xd,
  call0: CALL0_BASE + 0x10,
  ret: CALL0_BASE + 0x1c,
  callx0: CALL0_BASE + 0x35,
};
/**
 * The literal and addend of the windowed fixture, the kept addend, and the
 * mask-ROM address the second caller calls.
 */
export const XTENSA_CALL0_FIXTURE_VALUES = {
  literal: XTENSA_FIXTURE_LITERAL,
  addend: XTENSA_FIXTURE_ADDEND,
  kept: 5,
  rom: 0x40002000,
};
/** What `../c/xtensa-call0.c` keeps, passes and adds. */
export const XTENSA_CALL0_C_FIXTURE_VALUES = {
  mask: 0x5a,
  factor: 5,
  constant: 0x1234567,
};

const TEXT_OFFSET = 0x1000;
const descriptorText = (abi) => `USE_ABSOLUTE_LITERALS=0\nABI=${abi}\n`;

/** The `.xtensa.info` note GNU ld writes (56 bytes). */
const xtensaInfo = (abi) => {
  const name = Buffer.from("Xtensa_Info\0", "latin1");
  const descriptor = Buffer.alloc(32);
  descriptor.write(descriptorText(abi), "latin1");
  const header = Buffer.alloc(12);
  header.writeUInt32LE(name.length, 0);
  header.writeUInt32LE(descriptor.length, 4);
  header.writeUInt32LE(1, 8);
  return Buffer.concat([header, name, descriptor]);
};

const align = (value, alignment) => Math.ceil(value / alignment) * alignment;

const strings = (names) => {
  const offsets = {};
  const parts = [Buffer.alloc(1)];
  let length = 1;
  for (const name of names) {
    offsets[name] = length;
    const bytes = Buffer.from(`${name}\0`, "latin1");
    parts.push(bytes);
    length += bytes.length;
  }
  return { bytes: Buffer.concat(parts), offsets };
};

const WINDOWED = {
  text: XTENSA_FIXTURE_TEXT,
  base: BASE,
  symbols: XTENSA_FIXTURE_SYMBOLS,
  entry: "rea_xtensa_entry",
  abi: "0",
};
const CALL0 = {
  text: XTENSA_CALL0_FIXTURE_TEXT,
  base: CALL0_BASE,
  symbols: XTENSA_CALL0_FIXTURE_SYMBOLS,
  entry: "rea_xtensa_call0_entry",
  abi: "1",
};

/** The windowed fixture as ELF32 little-endian ET_EXEC bytes. */
export function xtensaFixtureBytes() {
  return layoutFixture(WINDOWED);
}

/** The call0 fixture, whose `.xtensa.info` declares ABI=1. */
export function xtensaCall0FixtureBytes() {
  return layoutFixture(CALL0);
}

/** Lay out ELF32 little-endian ET_EXEC bytes with one PT_LOAD and a symbol table. */
function layoutFixture({ text, base, symbols, entry, abi }) {
  const info = xtensaInfo(abi);
  const symbolNames = Object.keys(symbols);
  const strtab = strings(symbolNames);
  const shstrtab = strings([
    ".text",
    ".xtensa.info",
    ".symtab",
    ".strtab",
    ".shstrtab",
  ]);
  const symtab = Buffer.alloc(16 * (symbolNames.length + 1));
  symbolNames.forEach((name, index) => {
    const { address, size, type } = symbols[name];
    const at = 16 * (index + 1);
    symtab.writeUInt32LE(strtab.offsets[name], at);
    symtab.writeUInt32LE(address, at + 4);
    symtab.writeUInt32LE(size, at + 8);
    symtab[at + 12] = (1 << 4) | (type === "FUNC" ? 2 : 1); // STB_GLOBAL
    symtab.writeUInt16LE(1, at + 14); // .text
  });
  const infoOffset = TEXT_OFFSET + text.length;
  const symtabOffset = align(infoOffset + info.length, 4);
  const strtabOffset = symtabOffset + symtab.length;
  const shstrtabOffset = strtabOffset + strtab.bytes.length;
  const sectionOffset = align(shstrtabOffset + shstrtab.bytes.length, 4);
  const sections = [
    null,
    [".text", 1, 6, base, TEXT_OFFSET, text.length, 0, 0, 4, 0],
    [".xtensa.info", 7, 0, 0, infoOffset, info.length, 0, 0, 1, 0],
    [".symtab", 2, 0, 0, symtabOffset, symtab.length, 4, 1, 4, 16],
    [".strtab", 3, 0, 0, strtabOffset, strtab.bytes.length, 0, 0, 1, 0],
    [".shstrtab", 3, 0, 0, shstrtabOffset, shstrtab.bytes.length, 0, 0, 1, 0],
  ];
  const bytes = Buffer.alloc(sectionOffset + 40 * sections.length);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]); // ELF32, little-endian
  bytes.writeUInt16LE(2, 16); // ET_EXEC
  bytes.writeUInt16LE(94, 18); // EM_XTENSA
  bytes.writeUInt32LE(1, 20);
  bytes.writeUInt32LE(symbols[entry].address, 24);
  bytes.writeUInt32LE(52, 28);
  bytes.writeUInt32LE(sectionOffset, 32);
  bytes.writeUInt32LE(0x300, 36); // EF_XTENSA_XT_INSN | EF_XTENSA_XT_LIT
  bytes.writeUInt16LE(52, 40);
  bytes.writeUInt16LE(32, 42);
  bytes.writeUInt16LE(1, 44);
  bytes.writeUInt16LE(40, 46);
  bytes.writeUInt16LE(sections.length, 48);
  bytes.writeUInt16LE(sections.length - 1, 50);
  // PT_LOAD for .text, readable and executable.
  for (const [index, value] of [
    1,
    TEXT_OFFSET,
    base,
    base,
    text.length,
    text.length,
    5,
    0x1000,
  ].entries())
    bytes.writeUInt32LE(value, 52 + 4 * index);
  text.copy(bytes, TEXT_OFFSET);
  info.copy(bytes, infoOffset);
  symtab.copy(bytes, symtabOffset);
  strtab.bytes.copy(bytes, strtabOffset);
  shstrtab.bytes.copy(bytes, shstrtabOffset);
  sections.forEach((section, index) => {
    if (section === null) return;
    const [name, ...words] = section;
    const at = sectionOffset + 40 * index;
    bytes.writeUInt32LE(shstrtab.offsets[name], at);
    words.forEach((word, field) =>
      bytes.writeUInt32LE(word, at + 4 * (field + 1)),
    );
  });
  return bytes;
}

/** File offset of the `ABI=` digit in the one `.xtensa.info` descriptor. */
const abiDigitOffset = (bytes) => {
  const prefix = Buffer.from("USE_ABSOLUTE_LITERALS=0\nABI=", "latin1");
  const at = bytes.indexOf(prefix);
  if (at < 0 || bytes.lastIndexOf(prefix) !== at)
    throw new Error("Expected exactly one Xtensa_Info descriptor");
  return at + prefix.length;
};

/** Header-mutated copies test admission; they are not new producer claims. */
export function mutateXtensaFixture(bytes, change) {
  const copy = Buffer.from(bytes);
  if (change.flags !== undefined) copy.writeUInt32LE(change.flags, 36);
  if (change.type !== undefined) copy.writeUInt16LE(change.type, 16);
  if (change.abi !== undefined)
    copy.write(change.abi, abiDigitOffset(copy), "latin1");
  return copy;
}

const writeFixture = async (directory, name, bytes) => {
  const path = join(directory, name);
  await writeFile(path, bytes);
  return {
    path,
    bytes,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
};

/** Write the source-owned fixture; its target code is never executed. */
export function writeXtensaFixture(directory) {
  return writeFixture(directory, "xtensa-windowed.elf", xtensaFixtureBytes());
}

/** Write the source-owned call0 fixture; its target code is never executed. */
export function writeXtensaCall0Fixture(directory) {
  return writeFixture(directory, "xtensa-call0.elf", xtensaCall0FixtureBytes());
}

/**
 * Optional route: build the C fixture with a caller-supplied Espressif
 * compiler, for example xtensa-esp32-elf-gcc. The lane never acquires one.
 */
export function buildXtensaCFixture(directory, compiler) {
  return buildCFixture(directory, compiler, {
    source: "xtensa.c",
    output: "xtensa-c.elf",
    entry: "rea_xtensa_c_entry",
    flags: [],
  });
}

/**
 * Optional route: build the call0 C fixture with a caller-supplied compiler:
 * an ESP8266 compiler such as xtensa-lx106-elf-gcc, whose only ABI is call0,
 * or an Espressif ESP32 compiler with `-mabi=call0`.
 */
export function buildXtensaCall0CFixture(directory, compiler, flags, output) {
  return buildCFixture(directory, compiler, {
    source: "xtensa-call0.c",
    output,
    entry: "rea_xtensa_call0_c_entry",
    flags,
  });
}

async function buildCFixture(directory, compiler, fixture) {
  const source = fileURLToPath(
    new URL(`../c/${fixture.source}`, import.meta.url),
  );
  const path = join(directory, fixture.output);
  const args = [
    ...fixture.flags,
    "-O1",
    "-g",
    "-nostdlib",
    "-static",
    `-Wl,-e,${fixture.entry}`,
    "-Wl,--build-id=none",
    source,
    "-o",
    path,
  ];
  const options = { timeout: 60000, maxBuffer: 1024 * 1024 };
  const version = await execute(compiler, ["--version"], options);
  await execute(compiler, args, options);
  const bytes = await readFile(path);
  return {
    path,
    bytes,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    toolchain: {
      compiler: { command: compiler, version: version.stdout.split("\n")[0] },
      arguments: args,
    },
    source_sha256: createHash("sha256")
      .update(await readFile(source))
      .digest("hex"),
  };
}
