import { execFileSync } from "node:child_process";
import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";

import { ArtifactResourceScope } from "../../../src/resources/ArtifactResourceScope.js";
import { readGhidraLanguageCatalog } from "../../../src/ghidra/GhidraLanguageCatalog.js";
import { catalogLanguage } from "../../fixtures/ghidraLanguageCatalog.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const LIMIT = 4 * 1024 * 1024;
const OVERSIZED = "oversized.ldefs";

// Count bytes delivered from the oversized definition, whichever read API is used.
const { readBytes } = vi.hoisted(() => ({ readBytes: { value: 0 } }));
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  const tracked = (path: unknown) => String(path).endsWith(OVERSIZED);
  return {
    ...actual,
    readFile: async (...args: Parameters<typeof actual.readFile>) => {
      const bytes = await actual.readFile(...args);
      if (tracked(args[0])) readBytes.value += bytes.length;
      return bytes;
    },
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      if (!tracked(args[0])) return handle;
      const read = handle.read.bind(handle) as (
        ...readArgs: unknown[]
      ) => Promise<{ bytesRead: number }>;
      return Object.assign(handle, {
        read: async (...readArgs: unknown[]) => {
          const result = await read(...readArgs);
          readBytes.value += result.bytesRead;
          return result;
        },
      });
    },
  };
});

afterEach(() => {
  readBytes.value = 0;
});

it("reads an exact-limit definition while skipping its oversized sibling with bounded I/O", async () => {
  const root = await createTestTempDirectory("rea-ghidra-ldefs-bound-");
  const directory = join(root, "Ghidra/Processors/x86/data/languages");
  await mkdir(directory, { recursive: true });
  const definition = (id: string, size: number) => {
    const bytes = Buffer.alloc(size, 0x20);
    bytes.write(
      `<language_definitions><language id="${id}:LE:32:default"/></language_definitions>`,
    );
    return bytes;
  };
  const oversizedPath = join(directory, OVERSIZED);
  await writeFile(oversizedPath, definition("huge", LIMIT + 64 * 1024));
  const edge = definition("edge", LIMIT);
  await writeFile(join(directory, "edge.ldefs"), edge);

  expect(
    await readGhidraLanguageCatalog(root, new ArtifactResourceScope()),
  ).toEqual({
    // The digest covers every byte up to the limit, padding included.
    definitions: [
      catalogLanguage(
        "edge:LE:32:default",
        join(directory, "edge.ldefs"),
        edge,
      ),
    ],
    oversizedFiles: [oversizedPath],
  });
  expect(readBytes.value).toBeLessThanOrEqual(LIMIT + 1);
});

it("follows a symlinked definition file", async () => {
  const root = await createTestTempDirectory("rea-ghidra-ldefs-symlink-");
  const languages = join(root, "Ghidra/Processors/link/data/languages");
  await mkdir(languages, { recursive: true });
  const source = join(root, "source.xml");
  const document =
    '<language_definitions><language id="link:LE:32:default"/></language_definitions>';
  await writeFile(source, document);
  await symlink(source, join(languages, "link.ldefs"));
  const catalog = await readGhidraLanguageCatalog(
    root,
    new ArtifactResourceScope(),
  );
  // The entry names the link the installation lists, not its target.
  expect(catalog.definitions).toEqual([
    catalogLanguage(
      "link:LE:32:default",
      join(languages, "link.ldefs"),
      document,
    ),
  ]);
});

it.skipIf(process.platform === "win32")(
  "refuses a non-regular definition without waiting for a writer",
  async () => {
    const root = await createTestTempDirectory("rea-ghidra-ldefs-fifo-");
    const languages = join(root, "Ghidra/Processors/pipe/data/languages");
    await mkdir(languages, { recursive: true });
    execFileSync("mkfifo", [join(languages, "pipe.ldefs")]);
    const resources = new ArtifactResourceScope();
    await expect(
      readGhidraLanguageCatalog(root, resources),
    ).rejects.toMatchObject({ code: "ENOTFILE" });
    expect(resources.hasPending).toBe(false);
  },
);
