import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

// Optional verification tools only; the runtime reader starts no tool.
const compiler = process.env.REA_RISCV_CLANG ?? "clang";
const linker = process.env.REA_RISCV_LLD ?? "ld.lld";
const python = process.env.REA_ESPTOOL_PYTHON ?? "python3";
// Optional: an Xtensa ESP32 build when Espressif's GCC is supplied.
export const xtensa = process.env.REA_XTENSA_ESP32_GCC;
export const execute = promisify(execFile);
export const options = { maxBuffer: 16 * 1024 * 1024, timeout: 120_000 };
export const source = (name) =>
  fileURLToPath(
    new URL(`../../../tests/conformance/esp/${name}`, import.meta.url),
  );
const entrypoint = fileURLToPath(new URL("../../rea.mjs", import.meta.url));

/** Run esptool or espsecure through the caller-supplied Python. */
export const tool = async (module, args) => {
  const { stdout, stderr } = await execute(
    python,
    ["-m", module, ...args],
    options,
  );
  return `${stdout}${stderr}`;
};

const versionText = await tool("esptool", ["version"]);
const version = /\bv(\d+)\.(\d+)\.(\d+)\b/u.exec(versionText);
assert.ok(version, `Unrecognized esptool version: ${versionText}`);
export const esptoolVersion = version[0];
const v5 = Number(version[1]) >= 5;
/** esptool v5 spells commands and options with hyphens. */
export const spell = (v4, later) => (v5 ? later : v4);
export const compilerVersion = (
  await execute(compiler, ["--version"], options)
).stdout.split("\n")[0];

/** Build a RISC-V ELF from a conformance source; it is never run. */
export const buildElf = async (program, script, output) => {
  await execute(
    compiler,
    [
      "--target=riscv32-unknown-elf",
      "-march=rv32imc",
      "-mabi=ilp32",
      `--ld-path=${linker}`,
      "-nostdlib",
      "-static",
      "-fno-pic",
      "-Os",
      `-Wl,-T,${source(script)}`,
      "-Wl,--build-id=none",
      source(program),
      "-o",
      output,
    ],
    options,
  );
  return output;
};

export const elf2image = (chip, elf, output, extra = []) =>
  tool("esptool", [
    "--chip",
    chip,
    "elf2image",
    spell("--flash_mode", "--flash-mode"),
    "dio",
    spell("--flash_size", "--flash-size"),
    "4MB",
    ...extra,
    "-o",
    output,
    elf,
  ]);

/** Facts esptool image-info prints, read from its documented line formats. */
export const imageInfo = async (file, chip) => {
  const text = await tool("esptool", [
    ...(chip === undefined ? [] : ["--chip", chip]),
    ...(v5 ? ["image-info", file] : ["image_info", "--version", "2", file]),
  ]);
  const field = (label) =>
    new RegExp(`^${label}: (.+)$`, "mu").exec(text)?.[1]?.trim();
  const checksum =
    /^Checksum: 0x([0-9a-f]+) \((valid|invalid - calculated (?:0x)?([0-9a-f]+))\)$/mu.exec(
      text,
    );
  const hash = /^Validation hash: ([0-9a-f]{64}) \((valid|invalid)\)$/mu.exec(
    text,
  );
  return {
    detected: field("Detected image type"),
    entry: Number(field("Entry point")),
    chipId: Number(field("Chip ID")?.split(" ")[0]),
    segments: [
      ...text.matchAll(
        /^\s*(\d+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+\S.*$/gmu,
      ),
    ].map((row) => ({
      index: Number(row[1]),
      length: Number.parseInt(row[2], 16),
      address: Number.parseInt(row[3], 16),
      headerOffset: Number.parseInt(row[4], 16),
    })),
    checksum:
      checksum === null
        ? undefined
        : {
            stored: Number.parseInt(checksum[1], 16),
            valid: checksum[2] === "valid",
            computed: Number.parseInt(checksum[3] ?? checksum[1], 16),
          },
    hash:
      hash === null
        ? undefined
        : { computed: hash[1], valid: hash[2] === "valid" },
    project: field("Project name"),
    appVersion: field("App version"),
    elfSha256: field("ELF file SHA256"),
    idfVer: field("ESP-IDF"),
    secureVersion: field("Secure version"),
    bootloaderVersion: field("Bootloader version"),
    compileTime: field("Compile time"),
  };
};

/** REA's complete inline inventory for one file through the built CLI. */
export const inspect = async (file) => {
  const result = await execute(
    process.execPath,
    [entrypoint, "inspect-artifact", file, "--json"],
    { ...options, env: { ...process.env, REA_LOG_LEVEL: "silent" } },
  ).then(
    ({ stdout }) => ({ ok: true, stdout }),
    (failure) => ({ ok: false, stdout: `${failure.stdout}${failure.stderr}` }),
  );
  if (!result.ok) return { refused: result.stdout };
  const inventory = JSON.parse(result.stdout).normalized_result.substeps[0]
    .evidence.normalized_result;
  const rows = inventory.occurrences.filter((row) => row.logical_path !== ".");
  return {
    inventory,
    root: inventory.occurrences.find((row) => row.logical_path === ".")
      .format_metadata,
    segments: rows.filter(
      (row) => row.format_metadata?.kind === "esp-image-segment",
    ),
    signatures: rows.filter(
      (row) => row.format_metadata?.kind === "esp-image-signature-block",
    ),
  };
};

const assertDescriptorAgrees = (name, oracle, descriptor) => {
  if (oracle.project !== undefined) {
    assert.equal(descriptor.kind, "app", `${name} descriptor`);
    assert.equal(descriptor.project_name, oracle.project, name);
    assert.equal(descriptor.version, oracle.appVersion, name);
    assert.equal(descriptor.app_elf_sha256, oracle.elfSha256, name);
    assert.equal(descriptor.idf_ver, oracle.idfVer, name);
    assert.equal(String(descriptor.secure_version), oracle.secureVersion, name);
    assert.equal(
      `${descriptor.date} ${descriptor.time}`,
      oracle.compileTime,
      name,
    );
  }
  if (oracle.bootloaderVersion !== undefined) {
    assert.equal(descriptor.kind, "bootloader", `${name} descriptor`);
    assert.equal(String(descriptor.version), oracle.bootloaderVersion, name);
    assert.equal(descriptor.idf_ver, oracle.idfVer, name);
    assert.equal(descriptor.date_time, oracle.compileTime, name);
  }
};

/** Every fact both tools report for an image esptool can load. */
export const assertAgrees = (name, oracle, rea) => {
  assert.equal(rea.inventory.manifest.root_format, "esp-image", name);
  assert.equal(rea.root.header.entry_addr, oracle.entry, `${name} entry`);
  assert.equal(rea.root.header.chip_id, oracle.chipId, `${name} chip_id`);
  assert.deepEqual(
    rea.segments.map(({ format_metadata: segment }) => ({
      index: segment.index,
      length: segment.data_len,
      address: segment.load_addr,
      headerOffset: segment.header_offset,
    })),
    oracle.segments,
    `${name} segments`,
  );
  const { checksum, appended_sha256: digest } = rea.root;
  assert.equal(checksum.stored, oracle.checksum.stored, `${name} checksum`);
  assert.equal(checksum.computed, oracle.checksum.computed, name);
  assert.equal(checksum.status === "valid", oracle.checksum.valid, name);
  if (oracle.hash === undefined)
    assert.equal(digest.status, "not-appended", `${name} digest`);
  else {
    assert.equal(digest.computed, oracle.hash.computed, `${name} digest`);
    assert.equal(digest.status === "valid", oracle.hash.valid, name);
  }
  assertDescriptorAgrees(name, oracle, rea.root.descriptor);
};
