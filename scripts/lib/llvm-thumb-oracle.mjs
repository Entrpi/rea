// Independent oracle for annotated Thumb fixtures: LLVM assembles each source
// for its triple, the .text bytes must equal the fixture bytes, and
// llvm-objdump gives the mnemonic at each instruction offset. Data the source
// declares (an ARM `$d` mapping symbol) is not an instruction.
// sameThumbMnemonic compares Ghidra's mnemonic with LLVM's.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

/** Bytes of the `.text` section of a little-endian ELF32 relocatable object. */
const elf32Text = (object) => {
  assert.equal(
    object.readUInt32BE(0),
    0x7f454c46,
    "assembler output is not ELF",
  );
  assert.equal(object[4], 1, "assembler output is not ELF32");
  assert.equal(object[5], 1, "assembler output is not little-endian");
  const sectionHeaders = object.readUInt32LE(0x20);
  const entrySize = object.readUInt16LE(0x2e);
  const count = object.readUInt16LE(0x30);
  const names = sectionHeaders + object.readUInt16LE(0x32) * entrySize;
  const namesOffset = object.readUInt32LE(names + 0x10);
  for (let index = 0; index < count; index += 1) {
    const header = sectionHeaders + index * entrySize;
    const nameStart = namesOffset + object.readUInt32LE(header);
    const name = object.subarray(nameStart, object.indexOf(0, nameStart));
    if (name.toString("latin1") !== ".text") continue;
    const offset = object.readUInt32LE(header + 0x10);
    return object.subarray(offset, offset + object.readUInt32LE(header + 0x14));
  }
  throw new Error("assembler output has no .text section");
};

/**
 * Assemble `fixture.source` for its triple, and for `fixture.cpu` and
 * `fixture.floatAbi` when it names them, and require its bytes to equal
 * `fixture.code`. Returns LLVM's mnemonic for each instruction, keyed by image
 * offset.
 */
export const llvmThumbMnemonics = async (fixture, tools) => {
  const workspace = await mkdtemp(join(tmpdir(), "rea-thumb-oracle-"));
  // Optional extensions such as MVE are enabled by the CPU, not the triple.
  const cpu = (flag) =>
    fixture.cpu === undefined ? [] : [`${flag}=${fixture.cpu}`];
  // clang 19 refuses MVE under the default soft-float ABI.
  const floatAbi =
    fixture.floatAbi === undefined ? [] : [`-mfloat-abi=${fixture.floatAbi}`];
  try {
    const source = join(workspace, "fixture.s");
    const object = join(workspace, "fixture.o");
    await writeFile(source, fixture.source);
    await run(tools.clang, [
      `--target=${fixture.triple}`,
      ...cpu("-mcpu"),
      ...floatAbi,
      "-c",
      source,
      "-o",
      object,
    ]);
    assert.equal(
      elf32Text(await readFile(object)).toString("hex"),
      fixture.code,
      `LLVM assembles ${fixture.triple} source to different bytes`,
    );
    const { stdout } = await run(tools.objdump, [
      "-d",
      "--no-show-raw-insn",
      `--triple=${fixture.triple}`,
      ...cpu("--mcpu"),
      object,
    ]);
    const mnemonics = new Map();
    for (const line of stdout.split("\n")) {
      // `offset:` then data bytes, if any, then a tab and the mnemonic or,
      // for data, a directive such as `.short`.
      const match = /^\s*([0-9a-f]+):[^\t]*\t(\.?[a-z][a-z0-9.]*)/u.exec(line);
      if (match !== null && !match[2].startsWith("."))
        mnemonics.set(
          fixture.codeOffset + Number.parseInt(match[1], 16),
          match[2],
        );
    }
    assert.ok(mnemonics.size > 0, "llvm-objdump reported no instructions");
    return mnemonics;
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
};

/**
 * One spelling for both decoders, which write an encoding width (ldr.w) and an
 * IT-block condition (Ghidra mov.eq, LLVM moveq) differently.
 */
const canonicalMnemonic = (name) =>
  name
    ?.toLowerCase()
    .replace(/\.[nw]$/u, "")
    .replace(/\.(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)$/u, "$1");

/**
 * Whether Ghidra and LLVM name the same instruction. A data type that gives
 * only the element size (Ghidra vldrw.32) matches one that adds signedness
 * (LLVM vldrw.u32); opposite signedness does not.
 */
export const sameThumbMnemonic = (ghidra, llvm) => {
  const left = canonicalMnemonic(ghidra) ?? "";
  const right = canonicalMnemonic(llvm) ?? "";
  if (left === right) return true;
  const typed = /^(.+)\.([su]?)(8|16|32|64)$/u;
  const a = typed.exec(left);
  const b = typed.exec(right);
  return (
    a !== null &&
    b !== null &&
    a[1] === b[1] &&
    a[3] === b[3] &&
    (a[2] === "" || b[2] === "")
  );
};
