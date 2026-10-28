import { execFileSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it } from "vitest";

import { toolContract } from "../../../src/contracts/toolContracts.js";
import { rizinCommandLimitations } from "../../../src/rizin/RizinCommand.js";
import { createProviderEnvironmentMcpHarness } from "../../support/reverseDebuggerMcpTestHelpers.js";

// Real-provider gate for execute_rizin_command's decoder and map inputs. It
// runs the Rizin found on PATH and skips without one; put another Rizin's
// bin directory first on PATH to check that version.
const rizin = findRizin();
const banner = rizin === undefined ? "no Rizin on PATH" : versionBanner(rizin);

// Cortex-M vector table head (SP 0x20002000, Reset 0x08000109), then the
// Thumb instructions `bx lr` and `nop`.
const CORTEX_M_IMAGE = Buffer.from([
  0x00, 0x20, 0x00, 0x20, 0x09, 0x01, 0x00, 0x08, 0x70, 0x47, 0x00, 0xbf,
]);
// 6502 `nop; rts`; no host decodes 6502 by default.
const MOS_6502_IMAGE = Buffer.from([0xea, 0x60]);

const runRizin = async (
  input: Readonly<Record<string, string | number>>,
  image: Buffer,
) => {
  const directory = await mkdtemp(join(tmpdir(), "rea-rizin-decoder-"));
  const path = join(directory, "image.bin");
  await writeFile(path, image);
  const { client } = await createProviderEnvironmentMcpHarness({
    directory,
    clientName: "real-rizin-decoder-inputs",
    serverOptions: { environment: { REA_RIZIN_COMMAND: rizin! } },
  });
  const toolArguments = { path, ...input };
  const response = await client.callTool({
    name: "execute_rizin_command",
    arguments: toolArguments,
  });
  expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
  const evidence = toolContract("execute_rizin_command").outputSchema.parse(
    response.structuredContent,
  );
  expect(evidence.normalized_result.exit_code).toBe(0);
  expect(evidence.limitations).toEqual(
    expect.arrayContaining([
      ...rizinCommandLimitations({
        ...toolArguments,
        command: String(input.command),
      }),
    ]),
  );
  return {
    lines: evidence.normalized_result.stdout.trimEnd().split("\n"),
    stderr: evidence.normalized_result.stderr,
  };
};

const mapsOf = (line: string | undefined) =>
  JSON.parse(line ?? "null") as readonly {
    readonly fd: number;
    readonly delta: number;
    readonly from: number;
  }[];

it.skipIf(rizin === undefined)(
  `applies -a, -b, -e asm.cpu= and -m to a raw Cortex-M image (${banner})`,
  async () => {
    const { lines } = await runRizin(
      {
        command:
          "e asm.arch; e asm.bits; e asm.cpu; omlj; p8 1 @ 0x07ffffff; p8 12 @ 0x08000000; pi 1 @ 0x08000008",
        asm_arch: "arm",
        asm_bits: 16,
        asm_cpu: "cortexm",
        base_address: "0x08000000",
      },
      CORTEX_M_IMAGE,
    );
    expect(lines.slice(0, 3)).toEqual(["arm", "16", "cortexm"]);
    // One map: file offset 0 at the base address, nothing mapped below it.
    expect(mapsOf(lines[3])).toEqual([
      expect.objectContaining({ delta: 0, from: 0x08000000 }),
    ]);
    expect(lines.slice(4)).toEqual([
      "ff",
      CORTEX_M_IMAGE.toString("hex"),
      "bx lr",
    ]);
  },
);

it.skipIf(rizin === undefined)(
  `selects an arch that differs from the host default (${banner})`,
  async () => {
    const plain = await runRizin(
      { command: "e asm.arch; e asm.bits; omlj" },
      MOS_6502_IMAGE,
    );
    expect(plain.lines[0]).not.toBe("6502");
    expect(mapsOf(plain.lines[2])).toEqual([
      expect.objectContaining({ delta: 0, from: 0 }),
    ]);

    const selected = await runRizin(
      {
        command: "e asm.arch; e asm.bits; omlj; pi 2 @ 0x8000",
        asm_arch: "6502",
        asm_bits: 8,
        base_address: "0x8000",
      },
      MOS_6502_IMAGE,
    );
    expect(selected.lines.slice(0, 2)).toEqual(["6502", "8"]);
    expect(mapsOf(selected.lines[2])).toEqual([
      expect.objectContaining({ delta: 0, from: 0x8000 }),
    ]);
    expect(selected.lines.slice(3)).toEqual(["nop", "rts"]);
  },
);

it.skipIf(rizin === undefined)(
  `does not apply an arch or bits value that Rizin lacks (${banner})`,
  async () => {
    const plain = await runRizin({ command: "e asm.arch" }, MOS_6502_IMAGE);
    const unknown = await runRizin(
      {
        command: "e asm.arch; e asm.bits",
        asm_arch: "rea-no-such-arch",
        asm_bits: 16,
      },
      MOS_6502_IMAGE,
    );
    // Rizin exits 0, decodes with its default arch and names the value only
    // on stderr. Evidence carries the limitation for this case.
    expect(unknown.lines[0]).toBe(plain.lines[0]);
    expect(unknown.stderr).toContain("rea-no-such-arch");

    // ARM has no 8-bit mode. Rizin 0.9.1 keeps its default and reports the
    // value on stderr; Rizin 0.7.4 uses 16 without a message.
    const unsupported = await runRizin(
      { command: "e asm.bits", asm_arch: "arm", asm_bits: 8 },
      CORTEX_M_IMAGE,
    );
    expect(unsupported.lines[0]).not.toBe("8");
  },
);

function findRizin(): string | undefined {
  try {
    const path = execFileSync("which", ["rizin"], { encoding: "utf8" }).trim();
    return path === "" ? undefined : path;
  } catch {
    return undefined;
  }
}

function versionBanner(binary: string): string {
  try {
    return (
      execFileSync(binary, ["-v"], { encoding: "utf8" }).split("\n")[0] ??
      "unknown Rizin"
    ).trim();
  } catch {
    return "unknown Rizin";
  }
}
