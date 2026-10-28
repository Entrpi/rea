import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { expect, it } from "vitest";

import { PROVIDER_LANGUAGE_PAIRING } from "../../src/domain/rawBinary.js";
import { GHIDRA_LANGUAGE_DEFINITION_FILES } from "../../src/ghidra/GhidraLanguageCatalog.js";

const rawBinaryGuide = () => readFile(resolve("docs/raw-binary.md"), "utf8");

it("documents every language definition file that identity covers", async () => {
  const content = await rawBinaryGuide();
  const rows = content
    .split("\n")
    .filter((line) => /^\|\s*`(?:ldefs|sla|pspec|cspec)`/u.test(line))
    .map((line) =>
      line
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.trim()),
    );
  expect(rows).toEqual(
    GHIDRA_LANGUAGE_DEFINITION_FILES.map((file) => [
      `\`${file.role}\``,
      file.source,
    ]),
  );
});

it("documents every input a provider language refuses or requires", async () => {
  const section = (await rawBinaryGuide()).split("## Provider languages")[1];
  for (const rule of PROVIDER_LANGUAGE_PAIRING)
    expect(section).toContain(`\`${rule.field}\``);
});

it("names provider_language in the skill reference", async () => {
  const content = await readFile(
    resolve(
      ".agents/skills/reverse-engineer-anything/references/native-and-artifacts.md",
    ),
    "utf8",
  );
  expect(content).toContain("`provider_language`");
});
