import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { expect, it } from "vitest";
import {
  artifactFormatMetadataSchema,
  COMPARED_FORMAT_METADATA_KINDS,
} from "../../src/domain/artifactFormatMetadata.js";

const FORMAT_METADATA_KINDS = new Set<string>(
  artifactFormatMetadataSchema.options.map((option) => option.shape.kind.value),
);

it("names exactly the format metadata kinds that artifact comparison compares", async () => {
  const contracts = await readFile(resolve("docs/mcp-contracts.md"), "utf8");
  const paragraphs = contracts
    .split(/\n\s*\n/u)
    .filter((paragraph) =>
      paragraph.includes(
        "also compares the declarations in the `format_metadata`",
      ),
    );
  expect(paragraphs).toHaveLength(1);
  const named = [...(paragraphs[0] ?? "").matchAll(/`([^`]+)`/gu)]
    .map((match) => match[1] ?? "")
    .filter((token) => FORMAT_METADATA_KINDS.has(token));
  expect(new Set(named)).toEqual(new Set(COMPARED_FORMAT_METADATA_KINDS));
});
