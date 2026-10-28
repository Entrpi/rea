import { open, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { readArmElfAttributes } from "../../../src/application/ArmElfAttributes.js";
import { parseBinaryTarget } from "../../../src/application/BinaryTargetResolver.js";
import { ARM_BUILD_ATTRIBUTES_MAX_BYTES } from "../../../src/domain/armBuildAttributes.js";
import { ARM_ELF_HEADER } from "../../../src/domain/binaryTarget.fixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const SHT_ARM_ATTRIBUTES = 0x70000003;
// .ARM.attributes written by Clang and LLD 19.1.7 for thumbv7em-none-eabihf.
const CORTEX_M4F_ATTRIBUTES = Buffer.from(
  "4148000000616561626900013e00000043322e30390005636f727465782d6d3400060d074d080009020a060e0011011204140115001703180119011a021b011c011e01220124012601",
  "hex",
);
// Outside BinaryTargetResolver's initial 4 KiB header probe.
const PAYLOAD_OFFSET = 8192;

interface Section {
  readonly type: number;
  readonly payload: Buffer;
}

/** A little- or big-endian ELF32 EM_ARM executable with the given sections. */
const armElf = (
  sections: readonly Section[],
  options: { readonly little?: boolean; readonly sectionTable?: false } = {},
): Buffer => {
  const little = options.little ?? true;
  const size = sections.reduce(
    (total, { payload }) => total + payload.length,
    PAYLOAD_OFFSET,
  );
  const bytes = Buffer.alloc(size);
  const u16 = (value: number, offset: number) =>
    little
      ? bytes.writeUInt16LE(value, offset)
      : bytes.writeUInt16BE(value, offset);
  const u32 = (value: number, offset: number) =>
    little
      ? bytes.writeUInt32LE(value, offset)
      : bytes.writeUInt32BE(value, offset);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 1, little ? 1 : 2, 1]);
  u16(2, 16);
  u16(40, 18);
  u32(1, 20);
  u32(0x08000000, 24);
  u32(ARM_ELF_HEADER.flags, 36);
  u16(52, 40);
  u16(32, 42);
  u16(40, 46);
  if (options.sectionTable !== false) {
    u32(64, 32);
    u16(sections.length + 1, 48);
  }
  let offset = PAYLOAD_OFFSET;
  sections.forEach(({ type, payload }, index) => {
    const header = 64 + (index + 1) * 40;
    u32(type, header + 4);
    u32(offset, header + 16);
    u32(payload.length, header + 20);
    payload.copy(bytes, offset);
    offset += payload.length;
  });
  return bytes;
};

const writeFixture = async (bytes: Buffer): Promise<string> => {
  const directory = await createTestTempDirectory("rea-arm-attributes-test-");
  const path = join(directory, "firmware.elf");
  await writeFile(path, bytes);
  return path;
};

const resolved = async (bytes: Buffer) => {
  const path = await writeFixture(bytes);
  const result = await parseBinaryTarget(path);
  if (!result.ok) throw result.error;
  const target = result.value;
  if (
    target.kind !== "executable" ||
    target.format !== "elf" ||
    target.architecture !== "arm"
  )
    throw new Error("Expected a resolved ARM ELF executable");
  expect((await readFile(path)).equals(bytes)).toBe(true);
  return target.arm;
};

const attributes = (payload: Buffer): Section => ({
  type: SHT_ARM_ATTRIBUTES,
  payload,
});
const other: Section = { type: 1, payload: Buffer.from([0xaa, 0xbb]) };

describe("ARM ELF attributes at target resolution", () => {
  it("reads declarations found by section type beyond the header probe", async () => {
    expect(
      await resolved(armElf([other, attributes(CORTEX_M4F_ATTRIBUTES)])),
    ).toEqual({
      ...ARM_ELF_HEADER,
      attributes: {
        status: "declared",
        declarations: { cpuArch: 13, cpuArchProfile: 0x4d, vfpArgs: 1 },
      },
    });
  });

  it("records an inspected absence", async () => {
    expect((await resolved(armElf([other]))).attributes).toEqual({
      status: "absent",
    });
  });

  it.each([
    [
      "no section table",
      armElf([], { sectionTable: false }),
      "the image has no section header table",
    ],
    [
      "two attribute sections",
      armElf([
        attributes(CORTEX_M4F_ATTRIBUTES),
        attributes(CORTEX_M4F_ATTRIBUTES),
      ]),
      "the image has more than one attributes section",
    ],
    [
      "a section-scoped declaration",
      armElf([
        attributes(
          Buffer.from("411300000061656162690002090000000100060d", "hex"),
        ),
      ]),
      "section- and symbol-scoped attributes are not read",
    ],
    [
      "an empty attributes section",
      armElf([attributes(Buffer.alloc(0))]),
      `the attributes section has 0 bytes, outside the read bound of 1 to ${ARM_BUILD_ATTRIBUTES_MAX_BYTES}`,
    ],
    [
      "an attributes section past the read bound",
      armElf([attributes(Buffer.alloc(ARM_BUILD_ATTRIBUTES_MAX_BYTES + 1))]),
      `the attributes section has ${ARM_BUILD_ATTRIBUTES_MAX_BYTES + 1} bytes, outside the read bound of 1 to ${ARM_BUILD_ATTRIBUTES_MAX_BYTES}`,
    ],
  ])(
    "resolves with unknown declarations for %s",
    async (_name, bytes, reason) => {
      expect((await resolved(bytes)).attributes).toEqual({
        status: "unavailable",
        reason,
      });
    },
  );

  it("leaves big-endian images uninspected", async () => {
    const arm = await resolved(
      armElf([attributes(CORTEX_M4F_ATTRIBUTES)], { little: false }),
    );
    expect(arm.byteOrder).toBe("big");
    expect(arm.attributes).toBeUndefined();
  });
});

describe("ARM ELF attribute reader", () => {
  const read = async (
    bytes: Buffer,
    metadata = ARM_ELF_HEADER,
    checkCancelled: () => void = () => {},
  ) => {
    const handle = await open(await writeFixture(bytes), "r");
    try {
      return await readArmElfAttributes(handle, metadata, checkCancelled);
    } finally {
      await handle.close();
    }
  };

  it("fails when the header no longer matches the resolved identity", async () => {
    expect(
      await read(armElf([attributes(CORTEX_M4F_ATTRIBUTES)]), {
        ...ARM_ELF_HEADER,
        flags: 0x05000400,
      }),
    ).toEqual({
      ok: false,
      error: "the ARM ELF header no longer matches the resolved identity",
    });
  });

  it("preserves the caller's cancellation", async () => {
    const cancelled = new Error("cancelled");
    let checks = 0;
    await expect(
      read(armElf([attributes(CORTEX_M4F_ATTRIBUTES)]), ARM_ELF_HEADER, () => {
        checks += 1;
        if (checks > 3) throw cancelled;
      }),
    ).rejects.toBe(cancelled);
  });
});
