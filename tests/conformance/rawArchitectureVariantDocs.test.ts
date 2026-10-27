import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { expect, it } from "vitest";

import {
  RAW_ARCHITECTURE_VARIANT_NAMES,
  RAW_ARCHITECTURE_VARIANTS,
} from "../../src/domain/rawArchitectureVariant.js";
import { GHIDRA_RAW_VARIANT_LANGUAGES } from "../../src/ghidra/GhidraRawBinaryLanguage.js";

it("documents every architecture variant with its Ghidra decoder", async () => {
  const content = await readFile(resolve("docs/raw-binary.md"), "utf8");
  const rows = content
    .split("\n")
    .filter((line) => /^\|\s*`armv/u.test(line))
    .map((line) =>
      line
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.trim()),
    );
  expect(rows).toEqual(
    RAW_ARCHITECTURE_VARIANT_NAMES.map((name) => [
      `\`${name}\``,
      RAW_ARCHITECTURE_VARIANTS[name].label,
      `\`${GHIDRA_RAW_VARIANT_LANGUAGES[name]}\``,
      "`default`",
    ]),
  );
});

it("names every architecture variant in the skill reference", async () => {
  const content = await readFile(
    resolve(
      ".agents/skills/reverse-engineer-anything/references/native-and-artifacts.md",
    ),
    "utf8",
  );
  // The parenthesized list after `architecture_variant`, possibly wrapped.
  const list = /`architecture_variant` \(([^)]*)\)/u.exec(content)?.[1];
  expect(
    [...(list ?? "").matchAll(/`([^`]+)`/gu)].map((match) => match[1]),
  ).toEqual(RAW_ARCHITECTURE_VARIANT_NAMES);
});
