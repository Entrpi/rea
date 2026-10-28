import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { expect, it } from "vitest";

import {
  ARM_ELF_FLOAT_ABIS,
  ARM_ELF_M_PROFILE_ARCHITECTURES,
} from "../../src/domain/armBuildAttributes.js";
import {
  GHIDRA_ARM_ELF_DWARF_PROTOTYPES,
  GHIDRA_ARM_ELF_LANES,
} from "../../src/ghidra/GhidraArmProfile.js";
import { GHIDRA_VARIANT_LANGUAGES } from "../../src/ghidra/GhidraRawBinaryLanguage.js";

const tableRows = (content: string, first: RegExp) =>
  content
    .split("\n")
    .filter((line) => first.test(line))
    .map((line) =>
      line
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.trim()),
    );

it("documents every M-profile architecture with its lane", async () => {
  const content = await readFile(resolve("docs/ghidra-arm.md"), "utf8");
  expect(tableRows(content, /^\|\s*\d+\s*\|/u)).toEqual(
    ARM_ELF_M_PROFILE_ARCHITECTURES.map(({ cpuArch, label, variant }) => [
      String(cpuArch),
      label,
      `\`${variant}\``,
      `\`${GHIDRA_VARIANT_LANGUAGES[variant]}\``,
      `\`${GHIDRA_ARM_ELF_LANES[variant]}\``,
    ]),
  );
});

it("documents every float ABI reading and its DWARF prototype", async () => {
  const content = await readFile(resolve("docs/ghidra-arm.md"), "utf8");
  const prototypes: Partial<
    Record<string, { readonly callingConvention: string }>
  > = GHIDRA_ARM_ELF_DWARF_PROTOTYPES;
  expect(
    tableRows(content, /^\|\s*`[a-z]+`\s*\|\s*[^|-]/u).map(
      ([abi, , prototype]) => [abi, prototype],
    ),
  ).toEqual(
    ARM_ELF_FLOAT_ABIS.map((abi) => [
      `\`${abi}\``,
      prototypes[abi] === undefined
        ? "default"
        : `\`${prototypes[abi].callingConvention}\``,
    ]),
  );
});
