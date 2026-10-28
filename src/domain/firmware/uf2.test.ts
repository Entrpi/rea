import { expect, it } from "vitest";

import {
  createUf2Decoder,
  hasUf2Block,
  UF2_MAX_FILE_BYTES,
  type Uf2Image,
} from "./uf2.js";
import {
  RP2040_FAMILY,
  RP2350_ARM_S_FAMILY,
  RP2XXX_ABSOLUTE_FAMILY,
  UF2_FLAGS,
  patternBytes,
  uf2Block,
  uf2File,
  uf2Image,
} from "./uf2.fixture.js";

const decode = (bytes: Uint8Array, chunkSize = bytes.length || 1) => {
  const decoder = createUf2Decoder(bytes.length);
  if (!decoder.ok) throw new Error(decoder.error.message);
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const written = decoder.value.write(
      bytes.subarray(offset, offset + chunkSize),
    );
    if (!written.ok) return written;
  }
  return decoder.value.finish();
};

const image = (bytes: Uint8Array, chunkSize?: number): Uf2Image => {
  const decoded = decode(bytes, chunkSize);
  if (!decoded.ok) throw new Error(decoded.error.message);
  return decoded.value;
};

const regionFacts = ({ regions }: Uf2Image) =>
  regions.map(({ bytes, ...facts }) => ({ ...facts, length: bytes.length }));

it("recognizes only a complete first block with all three magic numbers", () => {
  const block = uf2Block({
    address: 0x1000_0000,
    payload: [1],
    blockNo: 0,
    numBlocks: 1,
  });
  expect(hasUf2Block(block)).toBe(true);
  expect(hasUf2Block(block.subarray(0, 511))).toBe(false);
  for (const magics of [
    [0x0a32_4656, 0x9e5d_5157, 0x0ab1_6f30],
    [0x0a32_4655, 0x9e5d_5156, 0x0ab1_6f30],
    [0x0a32_4655, 0x9e5d_5157, 0x0ab1_6f31],
  ] as const)
    expect(
      hasUf2Block(
        uf2Block({
          address: 0,
          payload: [1],
          blockNo: 0,
          numBlocks: 1,
          magics,
        }),
      ),
    ).toBe(false);
});

it("joins one family's numbered blocks into a region across chunk boundaries", () => {
  const bytes = patternBytes(1000);
  const file = uf2File(uf2Image(RP2040_FAMILY, 0x1000_0000, bytes));
  for (const chunkSize of [file.length, 512, 100, 7]) {
    const decoded = image(file, chunkSize);
    expect(decoded.complete).toBe(true);
    expect(decoded.limitations).toEqual([]);
    expect(regionFacts(decoded)).toEqual([
      {
        familyId: RP2040_FAMILY,
        start: 0x1000_0000,
        end: 0x1000_03e7,
        length: 1000,
        blockCount: 4,
        firstBlock: 0,
        lastBlock: 3,
      },
    ]);
    expect(Buffer.compare(decoded.regions[0]!.bytes, bytes)).toBe(0);
  }
  expect(image(file).metadata).toEqual({
    kind: "uf2",
    block_count: 4,
    trailing_bytes: 0,
    invalid_block_count: 0,
    flash_block_count: 4,
    not_main_flash_block_count: 0,
    file_container_block_count: 0,
    md5_block_count: 0,
    extension_tag_block_count: 0,
    family_count: 1,
    sequence_count: 1,
    missing_block_count: 0,
    repeated_block_count: 0,
    out_of_order_block_count: 0,
    block_number_out_of_range_count: 0,
    region_count: 1,
    data_bytes: 1000,
    duplicate_bytes: 0,
  });
});

it("keeps gaps between regions and sorts blocks that arrive out of order", () => {
  const payload = patternBytes(768);
  const [first, second, third, late] = [0, 1, 2, 3].map((blockNo) =>
    uf2Block({
      address: blockNo === 3 ? 0x1000_1000 : 0x1000_0000 + blockNo * 256,
      payload:
        blockNo === 3
          ? [0xaa, 0xbb]
          : payload.subarray(blockNo * 256, (blockNo + 1) * 256),
      blockNo,
      numBlocks: 4,
      familyId: RP2040_FAMILY,
    }),
  );
  const decoded = image(uf2File([late!, third!, first!, second!]));
  expect(Buffer.compare(decoded.regions[0]!.bytes, payload)).toBe(0);
  expect(regionFacts(decoded)).toEqual([
    expect.objectContaining({
      start: 0x1000_0000,
      end: 0x1000_02ff,
      blockCount: 3,
      firstBlock: 1,
      lastBlock: 3,
    }),
    expect.objectContaining({
      start: 0x1000_1000,
      end: 0x1000_1001,
      blockCount: 1,
      firstBlock: 0,
      lastBlock: 0,
    }),
  ]);
  expect(decoded.metadata).toMatchObject({
    out_of_order_block_count: 2,
    missing_block_count: 0,
    region_count: 2,
    data_bytes: 770,
  });
  expect(decoded.complete).toBe(true);
});

it("counts identical rewrites and refuses a conflicting rewrite of one address", () => {
  const first = uf2Block({
    address: 0x2000_0000,
    payload: [1, 2, 3, 4],
    blockNo: 0,
    numBlocks: 2,
    familyId: RP2040_FAMILY,
  });
  const same = uf2Block({
    address: 0x2000_0002,
    payload: [3, 4, 5],
    blockNo: 1,
    numBlocks: 2,
    familyId: RP2040_FAMILY,
  });
  const decoded = image(uf2File([first, same]));
  expect(decoded.metadata).toMatchObject({
    duplicate_bytes: 2,
    data_bytes: 5,
  });
  expect(
    Buffer.compare(decoded.regions[0]!.bytes, Uint8Array.from([1, 2, 3, 4, 5])),
  ).toBe(0);
  const different = uf2Block({
    address: 0x2000_0002,
    payload: [3, 9],
    blockNo: 1,
    numBlocks: 2,
    familyId: RP2040_FAMILY,
  });
  expect(decode(uf2File([first, different]))).toEqual({
    ok: false,
    error: {
      kind: "format",
      message:
        "family 0xe48bff56 (RP2040) address 0x20000003 is written with different values by block 0 (0x04) and block 1 (0x09)",
    },
  });
});

it("keeps families apart even when they target the same addresses", () => {
  // A Pico SDK universal image: an RP2350 absolute block, then RP2040 and RP2350 images.
  const absolute = uf2Block({
    address: 0x10ff_ff00,
    payload: new Uint8Array(256).fill(0xef),
    blockNo: 0,
    numBlocks: 2,
    familyId: RP2XXX_ABSOLUTE_FAMILY,
  });
  const decoded = image(
    uf2File([
      absolute,
      ...uf2Image(RP2040_FAMILY, 0x1000_0000, patternBytes(512, 1)),
      ...uf2Image(RP2350_ARM_S_FAMILY, 0x1000_0000, patternBytes(512, 2)),
    ]),
  );
  expect(
    decoded.regions.map(({ familyId, start, end }) => [familyId, start, end]),
  ).toEqual([
    [RP2040_FAMILY, 0x1000_0000, 0x1000_01ff],
    [RP2XXX_ABSOLUTE_FAMILY, 0x10ff_ff00, 0x10ff_ffff],
    [RP2350_ARM_S_FAMILY, 0x1000_0000, 0x1000_01ff],
  ]);
  expect(decoded.metadata).toMatchObject({
    family_count: 3,
    sequence_count: 3,
    missing_block_count: 1,
    duplicate_bytes: 0,
  });
  expect(decoded.complete).toBe(false);
  expect(decoded.limitations).toEqual([
    "UF2 numbering declares 1 block(s) that are absent: family 0xe48bff57 (RP2XXX_ABSOLUTE) has 1 of 2 numbered blocks.",
  ]);
});

it("reports numbered blocks that are absent and leaves coverage unknown", () => {
  const blocks = uf2Image(RP2040_FAMILY, 0x1000_0000, patternBytes(1024));
  const decoded = image(uf2File([blocks[0]!, blocks[1]!, blocks[3]!]));
  expect(decoded.complete).toBe(false);
  expect(decoded.metadata).toMatchObject({
    missing_block_count: 1,
    region_count: 2,
  });
  expect(decoded.limitations).toEqual([
    "UF2 numbering declares 1 block(s) that are absent: family 0xe48bff56 (RP2040) has 3 of 4 numbered blocks.",
  ]);
});

it("counts repeated numbering sequences without reporting absent blocks", () => {
  // esptool numbers each merged file from 0, so equal-sized files repeat numbers.
  const decoded = image(
    uf2File([
      ...uf2Image(0xc47e_5767, 0x0, patternBytes(512, 3)),
      ...uf2Image(0xc47e_5767, 0x8000, patternBytes(512, 4)),
    ]),
  );
  expect(decoded.metadata).toMatchObject({
    sequence_count: 1,
    repeated_block_count: 2,
    out_of_order_block_count: 1,
    missing_block_count: 0,
    family_count: 1,
    region_count: 2,
  });
  expect(decoded.complete).toBe(true);
  expect(decoded.regions[1]?.familyId).toBe(0xc47e_5767);
});

it("excludes not-main-flash and file-container blocks from regions", () => {
  const flash = uf2Block({
    address: 0x0,
    payload: [1, 2],
    blockNo: 0,
    numBlocks: 3,
  });
  const comment = uf2Block({
    address: 0x0,
    payload: [9, 9, 9],
    blockNo: 1,
    numBlocks: 3,
    flags: UF2_FLAGS.notMainFlash,
  });
  const decoded = image(uf2File([flash, comment]));
  expect(regionFacts(decoded)).toEqual([
    {
      familyId: null,
      start: 0,
      end: 1,
      length: 2,
      blockCount: 1,
      firstBlock: 0,
      lastBlock: 0,
    },
  ]);
  expect(decoded.metadata).toMatchObject({
    not_main_flash_block_count: 1,
    flash_block_count: 1,
    family_count: 0,
    missing_block_count: 1,
  });
  expect(decoded.limitations).toContain(
    "1 UF2 block(s) are flagged not main flash (flag 0x1); their 3 payload bytes are in no region.",
  );
  const file = uf2Block({
    address: 0,
    payload: [0x41],
    blockNo: 2,
    numBlocks: 3,
    fileSize: 1,
    flags: UF2_FLAGS.fileContainer | UF2_FLAGS.notMainFlash,
  });
  const contained = image(uf2File([flash, comment, file]));
  expect(contained.complete).toBe(false);
  expect(contained.metadata).toMatchObject({
    file_container_block_count: 1,
    not_main_flash_block_count: 1,
    missing_block_count: 0,
    region_count: 1,
  });
  expect(contained.limitations).toContain(
    "1 UF2 block(s) belong to file containers (flag 0x1000); their files were not reconstructed.",
  );
});

it("excludes invalid blocks and a truncated final block, leaving coverage unknown", () => {
  const blocks = uf2Image(RP2040_FAMILY, 0x1000_0000, patternBytes(768));
  const badEnd = uf2Block({
    address: 0x1000_0100,
    payload: patternBytes(256),
    blockNo: 1,
    numBlocks: 3,
    familyId: RP2040_FAMILY,
    magics: [0x0a32_4655, 0x9e5d_5157, 0],
  });
  const oversized = uf2Block({
    address: 0x1000_0300,
    payload: [1],
    declaredSize: 477,
    blockNo: 2,
    numBlocks: 3,
    familyId: RP2040_FAMILY,
  });
  const wrapping = uf2Block({
    address: 0xffff_ffff,
    payload: [1, 2],
    blockNo: 0,
    numBlocks: 1,
  });
  const decoded = image(
    uf2File([
      blocks[0]!,
      badEnd,
      blocks[2]!,
      oversized,
      wrapping,
      blocks[1]!.subarray(0, 100),
    ]),
  );
  expect(decoded.metadata).toMatchObject({
    block_count: 5,
    trailing_bytes: 100,
    invalid_block_count: 3,
    flash_block_count: 2,
    missing_block_count: 1,
    region_count: 2,
  });
  expect(decoded.complete).toBe(false);
  expect(decoded.limitations).toEqual([
    "UF2 file ends with 100 bytes after its last complete 512-byte block; the file may be truncated.",
    "3 UF2 block(s) are invalid and were excluded; the first is block 1 at byte offset 512: end magic number does not match.",
    "UF2 numbering declares 1 block(s) that are absent: family 0xe48bff56 (RP2040) has 2 of 3 numbered blocks.",
  ]);
});

it("reports block numbers outside their declared count", () => {
  const decoded = image(
    uf2File([
      uf2Block({ address: 0, payload: [1], blockNo: 1, numBlocks: 1 }),
      uf2Block({ address: 1, payload: [2], blockNo: 0, numBlocks: 0 }),
    ]),
  );
  expect(decoded.metadata).toMatchObject({
    block_number_out_of_range_count: 2,
    sequence_count: 0,
    region_count: 1,
    data_bytes: 2,
  });
  expect(decoded.complete).toBe(false);
});

it("counts MD5 and extension-tag flags as declared facts", () => {
  const decoded = image(
    uf2File([
      uf2Block({
        address: 0,
        payload: [1],
        blockNo: 0,
        numBlocks: 2,
        flags: UF2_FLAGS.md5,
      }),
      uf2Block({
        address: 1,
        payload: [2],
        blockNo: 1,
        numBlocks: 2,
        flags: UF2_FLAGS.extensionTags,
      }),
    ]),
  );
  expect(decoded.metadata).toMatchObject({
    md5_block_count: 1,
    extension_tag_block_count: 1,
    region_count: 1,
  });
});

it("refuses files above the fixed ceiling and too many discontiguous runs", () => {
  expect(createUf2Decoder(UF2_MAX_FILE_BYTES + 1)).toMatchObject({
    ok: false,
    error: { kind: "limit", boundary: "file-size" },
  });
  const blocks = Array.from({ length: 65_537 }, (_, index) =>
    uf2Block({ address: index * 2, payload: [1], blockNo: 0, numBlocks: 1 }),
  );
  expect(decode(uf2File(blocks), 512 * 1024)).toMatchObject({
    ok: false,
    error: { kind: "limit", boundary: "capacity" },
  });
});
