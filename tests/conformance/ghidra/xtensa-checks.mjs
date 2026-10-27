import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execute = promisify(execFile);
export const XTENSA_LANGUAGE = "Xtensa:LE:32:default";
export const XTENSA_COMPILER_SPEC = "default";

const field = (text, expression, label) => {
  const matches = [...text.matchAll(expression)];
  assert.equal(matches.length, 1, `Missing or ambiguous readelf ${label}`);
  return matches[0][1].trim();
};

/**
 * Parse the GNU or LLVM `readelf -h -s -n -W` fields the lane compares with
 * REA: header declarations, symbol values, and the `Xtensa_Info` note text.
 */
export function parseXtensaReadelf(text, names) {
  assert.equal(field(text, /^\s*Class:\s*(.+)$/gmu, "class"), "ELF32");
  const byteOrder = field(
    text,
    /^\s*Data:.*?,\s*(little|big) endian\s*$/gmu,
    "byte order",
  );
  assert.match(field(text, /^\s*Type:\s*(.+)$/gmu, "type"), /^EXEC\b/u);
  assert.match(field(text, /^\s*Machine:\s*(.+)$/gmu, "machine"), /Xtensa/u);
  const flags = Number(field(text, /^\s*Flags:\s*(0x[\da-f]+)/gmu, "flags"));
  const symbols = {};
  for (const name of names) {
    const value = field(
      text,
      new RegExp(
        `^\\s*\\d+:\\s+([\\da-f]+)\\s+\\d+\\s+(?:FUNC|OBJECT)\\s+GLOBAL\\s+\\S+\\s+\\d+\\s+${name}\\s*$`,
        "gmu",
      ),
      `symbol ${name}`,
    );
    symbols[name] = `0x${BigInt(`0x${value}`).toString(16)}`;
  }
  const note = field(
    text,
    /^\s*Xtensa_Info\s+0x[\da-f]+\s+.*?description data:\s*((?:[\da-f]{2}\s*)+)$/gmsu,
    "Xtensa_Info note",
  );
  const descriptor = Buffer.from(note.replaceAll(/\s+/gu, ""), "hex")
    .toString("latin1")
    .replace(/\0+$/u, "");
  const abiLine = descriptor
    .split("\n")
    .find((line) => line.startsWith("ABI="));
  assert.ok(abiLine, "Xtensa_Info note declares no ABI");
  return {
    xtensa: {
      elfClass: 32,
      byteOrder,
      type: 2,
      flags,
      abi: {
        status: "declared",
        abi: abiLine === "ABI=0" ? "windowed" : "call0",
      },
    },
    symbols,
    descriptor,
  };
}

/** Independent reader is a bounded lane prerequisite, never an REA provider. */
export async function inspectXtensaReadelf(path, names) {
  const command = process.env.REA_XTENSA_READELF ?? "readelf";
  const options = {
    env: { ...process.env, LC_ALL: "C" },
    timeout: 10000,
    maxBuffer: 1024 * 1024,
  };
  const version = await execute(command, ["--version"], options);
  assert.match(
    version.stdout,
    /\b(?:GNU readelf|LLVM)\b/u,
    "This lane requires GNU or LLVM readelf",
  );
  const result = await execute(
    command,
    ["-h", "-s", "-n", "-W", path],
    options,
  );
  assert.equal(result.stderr.trim(), "", "Unexpected readelf diagnostics");
  return {
    ...parseXtensaReadelf(result.stdout, names),
    command,
    version: version.stdout.split("\n")[0].trim(),
  };
}

/** Decoded fixture instructions, as annotated in xtensa-fixture.mjs. */
export function assertXtensaFixtureInstructions(instructions, addresses) {
  const at = (name) => instructions[name];
  for (const [name, mnemonic, bytes] of [
    ["entry", "entry", "364100"],
    ["l32r", "l32r", "a1feff"],
    ["call8", "call8", "a50000"],
    ["retw", "retw.n", "1df0"],
  ]) {
    assert.equal(at(name).status, "decoded", `${name} was not decoded`);
    assert.equal(at(name).architecture, XTENSA_LANGUAGE);
    assert.equal(at(name).mnemonic?.toLowerCase(), mnemonic);
    assert.equal(at(name).bytes, bytes);
  }
  assert.equal(at("call8").flow.kind, "call");
  assert.deepEqual(
    at("call8").flow.direct_destinations.map((value) => BigInt(value)),
    [BigInt(addresses.leaf)],
  );
  assert.equal(at("retw").flow.kind, "return");
  // The literal load reads the word below it; Ghidra records that read.
  assert.ok(
    at("l32r").references.some(
      (reference) =>
        BigInt(reference.target_address) === BigInt(addresses.literal),
    ),
    `l32r has no reference to its literal: ${JSON.stringify(at("l32r").references)}`,
  );
}

/**
 * The windowed caller passes the literal through call8 (a10 becomes the
 * callee's a2) and returns the callee's result; the leaf adds its addend.
 */
export function assertXtensaFixturePseudocode(entry, leaf, values) {
  assert.match(
    leaf,
    new RegExp(
      `\\+\\s*(?:${values.addend}|0x${values.addend.toString(16)})\\b`,
      "u",
    ),
    `leaf decompilation lacks the addend: ${leaf}`,
  );
  assert.match(
    entry,
    /\brea_xtensa_leaf\s*\(/u,
    `entry lacks the call: ${entry}`,
  );
  assert.match(
    entry,
    new RegExp(`0x${values.literal.toString(16)}\\b`, "iu"),
    `entry lacks the l32r literal as the call argument: ${entry}`,
  );
}
