import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * One build per M-profile variant, ARMv7E-M with each float ABI (soft, softfp
 * and hard), an ARMv6-M image linked at 0x0, and an A-profile control that
 * keeps Ghidra's header-based selection. `cpuArch` is what LLVM declares in
 * Tag_CPU_arch. The Cortex-M55 build is hard-float, so the v8-m decoder also
 * decodes VFP code; the v8-M builds are soft-float.
 */
export const CORTEX_M_ELF_BUILDS = [
  {
    name: "armv6-m",
    triple: "thumbv6m-none-eabi",
    cpu: "cortex-m0",
    floatAbi: "soft",
    base: 0x08000000,
    variant: "armv6-m",
    cpuArch: 12,
  },
  {
    name: "armv6-m-base0",
    triple: "thumbv6m-none-eabi",
    cpu: "cortex-m0",
    floatAbi: "soft",
    base: 0,
    variant: "armv6-m",
    cpuArch: 12,
  },
  {
    name: "armv7-m",
    triple: "thumbv7m-none-eabi",
    cpu: "cortex-m3",
    floatAbi: "soft",
    base: 0x08000000,
    variant: "armv7-m",
    cpuArch: 10,
  },
  {
    name: "armv7e-m-soft",
    triple: "thumbv7em-none-eabi",
    cpu: "cortex-m4",
    floatAbi: "soft",
    base: 0x08000000,
    variant: "armv7e-m",
    cpuArch: 13,
  },
  {
    name: "armv7e-m-hard",
    triple: "thumbv7em-none-eabihf",
    cpu: "cortex-m4",
    fpu: "fpv4-sp-d16",
    floatAbi: "hard",
    base: 0x08000000,
    variant: "armv7e-m",
    cpuArch: 13,
  },
  {
    name: "armv7e-m-softfp",
    triple: "thumbv7em-none-eabi",
    cpu: "cortex-m4",
    fpu: "fpv4-sp-d16",
    floatAbi: "softfp",
    base: 0x08000000,
    variant: "armv7e-m",
    cpuArch: 13,
  },
  {
    name: "armv8-m.base",
    triple: "thumbv8m.base-none-eabi",
    cpu: "cortex-m23",
    floatAbi: "soft",
    base: 0x08000000,
    variant: "armv8-m.base",
    cpuArch: 16,
  },
  {
    name: "armv8-m.main",
    triple: "thumbv8m.main-none-eabi",
    cpu: "cortex-m33",
    floatAbi: "soft",
    base: 0x08000000,
    variant: "armv8-m.main",
    cpuArch: 17,
  },
  {
    name: "armv8.1-m.main",
    triple: "thumbv8.1m.main-none-eabihf",
    cpu: "cortex-m55",
    floatAbi: "hard",
    base: 0x08000000,
    variant: "armv8.1-m.main",
    cpuArch: 21,
  },
  {
    name: "armv7-a",
    triple: "armv7a-none-eabihf",
    cpu: "cortex-a9",
    fpu: "vfpv3-d16",
    floatAbi: "hard",
    base: 0x08000000,
    variant: null,
    cpuArch: 10,
  },
];

/** Symbols the lane looks up; absent ones are omitted from `symbols`. */
export const CORTEX_M_ELF_SYMBOLS = [
  "Reset_Handler",
  "SysTick_Handler",
  "Default_Handler",
  "rea_cm_vectors",
  "rea_cm_fadd",
  "rea_cm_fpick",
  "rea_cm_dpick",
  "rea_cm_primask",
  "rea_cm_msplim",
  "rea_cm_sum",
];

const hex = (value) => `0x${value.toString(16)}`;

const linkerScript = (base) => `MEMORY
{
  FLASH (rx) : ORIGIN = ${hex(base)}, LENGTH = 64K
  RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 16K
}
ENTRY(Reset_Handler)
SECTIONS
{
  .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
  .text : { *(.text*) *(.rodata*) } > FLASH
  .data : { *(.data*) } > RAM AT > FLASH
  .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
  _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
`;

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Symbol addresses from LLVM, with the Thumb bit cleared from code addresses. */
const symbolAddresses = async (tools, path) => {
  const { stdout } = await tools.commands.exec(
    tools.readelf,
    ["--wide", "-s", path],
    {
      timeout: 30000,
    },
  );
  const symbols = {};
  for (const line of stdout.split("\n")) {
    const fields = line.trim().split(/\s+/u);
    const name = fields[7];
    if (fields.length < 8 || !CORTEX_M_ELF_SYMBOLS.includes(name)) continue;
    const value = Number.parseInt(fields[1], 16);
    symbols[name] = hex(fields[3] === "FUNC" ? value & ~1 : value);
  }
  return symbols;
};

/** The attribute and header facts LLVM reads, the lane's independent oracle. */
export const readelfArmFacts = async (tools, path) => {
  const header = await tools.commands.exec(tools.readelf, ["-h", path], {
    timeout: 30000,
  });
  const flags = /Flags:\s+(0x[0-9a-f]+)/u.exec(header.stdout)?.[1];
  const { stdout } = await tools.commands.exec(
    tools.readelf,
    ["--arch-specific", path],
    {
      timeout: 30000,
    },
  );
  // Each attribute block names its numeric tag and, for ULEB128 tags, a number.
  const values = new Map();
  for (const block of stdout.split("Attribute {").slice(1)) {
    const tag = /^\s*Tag: (\d+)\s*$/mu.exec(block)?.[1];
    const value = /^\s*Value: (\d+)\s*$/mu.exec(block)?.[1];
    if (tag !== undefined && value !== undefined)
      values.set(Number(tag), Number(value));
  }
  const tag = (number) => values.get(number) ?? null;
  return {
    flags: flags === undefined ? null : Number.parseInt(flags, 16),
    cpu_arch: tag(6),
    cpu_arch_profile: tag(7),
    vfp_args: tag(28),
  };
};

/**
 * Build every source-owned image, unstripped with DWARF and stripped of
 * symbols and debug sections. Never execute target code.
 *
 * `tools.commands` is the caller's verifier command owner: each tool runs as
 * an owned process tree with a deadline.
 */
export async function buildCortexMElfFixtures(directory, tools) {
  const source = fileURLToPath(new URL("../c/cortex-m.c", import.meta.url));
  const vectors = fileURLToPath(
    new URL("./cortex-m-vectors.S", import.meta.url),
  );
  const version = await tools.commands.exec(tools.clang, ["--version"], {
    timeout: 10000,
  });
  const fixtures = [];
  for (const build of CORTEX_M_ELF_BUILDS) {
    const script = join(directory, `${build.name}.ld`);
    await writeFile(script, linkerScript(build.base));
    const path = join(directory, `${build.name}.elf`);
    const stripped = join(directory, `${build.name}.stripped.elf`);
    const args = [
      `--target=${build.triple}`,
      `-mcpu=${build.cpu}`,
      `-mfloat-abi=${build.floatAbi}`,
      ...(build.fpu === undefined ? [] : [`-mfpu=${build.fpu}`]),
      "-O1",
      "-g",
      "-ffreestanding",
      "-fno-builtin",
      "-nostdlib",
      `-fuse-ld=${tools.lld}`,
      `-Wl,-T,${script}`,
      "-Wl,--build-id=none",
      // C first: LLD keeps the first input's .ARM.attributes section.
      source,
      vectors,
      "-o",
      path,
    ];
    await tools.commands.exec(tools.clang, args, { timeout: 60000 });
    await tools.commands.exec(
      tools.strip,
      ["--strip-all", "-o", stripped, path],
      {
        timeout: 30000,
      },
    );
    const bytes = await readFile(path);
    if (
      bytes.toString("hex", 0, 4) !== "7f454c46" ||
      bytes[4] !== 1 ||
      bytes[5] !== 1 ||
      bytes.readUInt16LE(16) !== 2 ||
      bytes.readUInt16LE(18) !== 40
    )
      throw new Error(
        `Compiler did not produce a little-endian ELF32 ARM executable for ${build.name}`,
      );
    fixtures.push({
      ...build,
      path,
      stripped,
      sha256: sha256(bytes),
      stripped_sha256: sha256(await readFile(stripped)),
      entry: hex(bytes.readUInt32LE(24) & ~1),
      symbols: await symbolAddresses(tools, path),
      readelf: await readelfArmFacts(tools, path),
      stripped_readelf: await readelfArmFacts(tools, stripped),
      arguments: args,
    });
  }
  return {
    compiler: version.stdout.split("\n")[0]?.trim(),
    source_sha256: sha256(await readFile(source)),
    vectors_sha256: sha256(await readFile(vectors)),
    fixtures,
  };
}

/**
 * LLVM's instructions for one function in address order: the mnemonic and,
 * for a direct branch, its target.
 */
export const llvmFunctionInstructions = async (tools, path, symbol) => {
  const { stdout } = await tools.commands.exec(
    tools.objdump,
    ["-d", "--no-show-raw-insn", `--disassemble-symbols=${symbol}`, path],
    { timeout: 30000 },
  );
  const instructions = [];
  for (const line of stdout.split("\n")) {
    const match = /^\s*([0-9a-f]+):\s+([a-z][\w.]*)/u.exec(line);
    if (match === null) continue;
    // llvm-objdump names a direct target with its symbol: 0x80000de <f+0x16>.
    const target = /\b0x([0-9a-f]+) <[^>]+>/u.exec(line)?.[1];
    instructions.push({
      address: hex(Number.parseInt(match[1], 16)),
      mnemonic: match[2],
      ...(target === undefined
        ? {}
        : { target: hex(Number.parseInt(target, 16)) }),
    });
  }
  return instructions;
};
