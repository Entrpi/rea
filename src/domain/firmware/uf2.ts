import type { Uf2Metadata } from "../artifactFormatMetadata.js";
import { err, ok, type Result } from "../result.js";
import { mergeArenaRuns, type RunConflict } from "./addressRuns.js";
import { uf2FamilyName } from "./uf2Families.js";

/** Every UF2 block is 512 bytes: a 32-byte header, 476 data bytes, an end magic. */
export const UF2_BLOCK_BYTES = 512;
const UF2_DATA_OFFSET = 32;
const UF2_DATA_BYTES = 476;
const UF2_MAGIC_START0 = 0x0a32_4655;
const UF2_MAGIC_START1 = 0x9e5d_5157;
const UF2_MAGIC_END = 0x0ab1_6f30;
const UF2_FLAG_NOT_MAIN_FLASH = 0x0000_0001;
const UF2_FLAG_FILE_CONTAINER = 0x0000_1000;
const UF2_FLAG_FAMILY_ID = 0x0000_2000;
const UF2_FLAG_MD5 = 0x0000_4000;
const UF2_FLAG_EXTENSION_TAGS = 0x0000_8000;
const ADDRESS_SPACE = 0x1_0000_0000;
/** Sequences named in one numbering limitation before the rest are counted. */
const NAMED_SEQUENCES = 4;

/**
 * Fixed whole-file ceiling, as for Intel HEX; configurable ceilings are
 * tracked in #6176. Decoded bytes stay below 476/512 of it.
 */
export const UF2_MAX_FILE_BYTES = 128 * 1024 * 1024;
/** Address-adjacent block runs retained before regions are merged. */
export const UF2_MAX_RUNS = 65_536;

/** A whole-file refusal; no partial regions accompany it. */
export interface Uf2Failure {
  readonly kind: "format" | "limit";
  readonly message: string;
  readonly boundary?: "file-size" | "capacity";
}

/** Decoded bytes for one family's address-contiguous range; `end` is inclusive. */
export interface Uf2Region {
  /** The declared familyID, or null when the block did not set flag 0x2000. */
  readonly familyId: number | null;
  readonly start: number;
  readonly end: number;
  readonly bytes: Uint8Array;
  readonly blockCount: number;
  /** Zero-based positions of the contributing blocks in the file. */
  readonly firstBlock: number;
  readonly lastBlock: number;
}

export interface Uf2Image {
  readonly metadata: Uf2Metadata;
  /** Ordered by family, with undeclared families first, then by address. */
  readonly regions: readonly Uf2Region[];
  readonly complete: boolean;
  readonly limitations: readonly string[];
}

export interface Uf2Decoder {
  /** Decode the next file bytes; a block may span chunks. */
  write(chunk: Uint8Array): Result<void, Uf2Failure>;
  /** Account for a partial final block, then merge runs into regions. */
  finish(): Result<Uf2Image, Uf2Failure>;
}

/** Consecutive main-flash blocks of one family whose addresses continue each other. */
interface BlockRun {
  readonly familyId: number | null;
  readonly address: number;
  readonly offset: number;
  length: number;
  blockCount: number;
  readonly firstBlock: number;
  lastBlock: number;
}

/** Blocks sharing a familyID (or none) and a declared block count. */
interface NumberingSequence {
  readonly familyId: number | null;
  readonly declared: number;
  readonly seen: Set<number>;
  previous: number;
}

const readUint32 = (bytes: Uint8Array, offset: number): number =>
  ((bytes[offset] ?? 0) |
    ((bytes[offset + 1] ?? 0) << 8) |
    ((bytes[offset + 2] ?? 0) << 16) |
    ((bytes[offset + 3] ?? 0) << 24)) >>>
  0;

const hex32 = (value: number): string =>
  `0x${value.toString(16).padStart(8, "0")}`;

const familyText = (familyId: number | null): string => {
  if (familyId === null) return "no familyID";
  const name = uf2FamilyName(familyId);
  return name === null
    ? `family ${hex32(familyId)}`
    : `family ${hex32(familyId)} (${name})`;
};

/** Recognize a file only by a complete first block with all three magic numbers. */
export const hasUf2Block = (prefix: Uint8Array): boolean =>
  prefix.length >= UF2_BLOCK_BYTES &&
  readUint32(prefix, 0) === UF2_MAGIC_START0 &&
  readUint32(prefix, 4) === UF2_MAGIC_START1 &&
  readUint32(prefix, UF2_BLOCK_BYTES - 4) === UF2_MAGIC_END;

/** Start a block decoder whose arena is bounded by the admitted file size. */
export const createUf2Decoder = (
  fileBytes: number,
): Result<Uf2Decoder, Uf2Failure> =>
  Number.isSafeInteger(fileBytes) &&
  fileBytes >= 0 &&
  fileBytes <= UF2_MAX_FILE_BYTES
    ? ok(new StreamingUf2Decoder(fileBytes))
    : err({
        kind: "limit",
        boundary: "file-size",
        message: `file is ${String(fileBytes)} bytes, exceeding the fixed ${String(UF2_MAX_FILE_BYTES)}-byte (128 MiB) ceiling`,
      });

class StreamingUf2Decoder implements Uf2Decoder {
  readonly #block = new Uint8Array(UF2_BLOCK_BYTES);
  readonly #runs: BlockRun[] = [];
  readonly #sequences = new Map<string, NumberingSequence>();
  readonly #families = new Set<number>();
  #arena: Uint8Array;
  #arenaUsed = 0;
  #blockLength = 0;
  #blockCount = 0;
  #invalid = 0;
  #firstInvalid:
    | { readonly block: number; readonly reason: string }
    | undefined;
  #flash = 0;
  #notMainFlash = 0;
  #notMainFlashBytes = 0;
  #fileContainer = 0;
  #md5 = 0;
  #extensionTags = 0;
  #repeated = 0;
  #outOfOrder = 0;
  #outOfRange = 0;

  constructor(fileBytes: number) {
    this.#arena = new Uint8Array(
      Math.floor(fileBytes / UF2_BLOCK_BYTES) * UF2_DATA_BYTES,
    );
  }

  write(chunk: Uint8Array): Result<void, Uf2Failure> {
    let from = 0;
    while (from < chunk.length) {
      const count = Math.min(
        UF2_BLOCK_BYTES - this.#blockLength,
        chunk.length - from,
      );
      this.#block.set(chunk.subarray(from, from + count), this.#blockLength);
      this.#blockLength += count;
      from += count;
      if (this.#blockLength < UF2_BLOCK_BYTES) break;
      this.#blockLength = 0;
      const decoded = this.#decodeBlock(this.#block);
      if (!decoded.ok) return decoded;
    }
    return ok(undefined);
  }

  finish(): Result<Uf2Image, Uf2Failure> {
    const merged = mergeRuns(this.#runs, this.#arena);
    this.#arena = new Uint8Array(0);
    if (!merged.ok) return merged;
    const { regions, duplicateBytes } = merged.value;
    const limitations = this.#limitations();
    return ok({
      metadata: this.#metadata(regions, duplicateBytes),
      regions,
      complete: limitations.unknown.length === 0,
      limitations: [...limitations.unknown, ...limitations.known],
    });
  }

  #decodeBlock(block: Uint8Array): Result<void, Uf2Failure> {
    const index = this.#blockCount;
    this.#blockCount += 1;
    const flags = readUint32(block, 8);
    const address = readUint32(block, 12);
    const size = readUint32(block, 16);
    const fault =
      readUint32(block, 0) !== UF2_MAGIC_START0 ||
      readUint32(block, 4) !== UF2_MAGIC_START1
        ? "start magic numbers do not match"
        : readUint32(block, UF2_BLOCK_BYTES - 4) !== UF2_MAGIC_END
          ? "end magic number does not match"
          : size > UF2_DATA_BYTES
            ? `payload size ${String(size)} exceeds the ${String(UF2_DATA_BYTES)}-byte data area`
            : address + size > ADDRESS_SPACE
              ? `payload at ${hex32(address)} with ${String(size)} bytes wraps past 0xffffffff`
              : undefined;
    if (fault !== undefined) {
      this.#invalid += 1;
      this.#firstInvalid ??= { block: index, reason: fault };
      return ok(undefined);
    }
    const familyId =
      (flags & UF2_FLAG_FAMILY_ID) !== 0 ? readUint32(block, 28) : null;
    if ((flags & UF2_FLAG_MD5) !== 0) this.#md5 += 1;
    if ((flags & UF2_FLAG_EXTENSION_TAGS) !== 0) this.#extensionTags += 1;
    this.#number(familyId, readUint32(block, 24), readUint32(block, 20));
    // The file-container flag overrides not-main-flash: such blocks hold files.
    if ((flags & UF2_FLAG_FILE_CONTAINER) !== 0) {
      this.#fileContainer += 1;
      return ok(undefined);
    }
    if ((flags & UF2_FLAG_NOT_MAIN_FLASH) !== 0) {
      this.#notMainFlash += 1;
      this.#notMainFlashBytes += size;
      return ok(undefined);
    }
    this.#flash += 1;
    if (familyId !== null) this.#families.add(familyId);
    return this.#addData(
      index,
      familyId,
      address,
      block.subarray(UF2_DATA_OFFSET, UF2_DATA_OFFSET + size),
    );
  }

  /** Numbering is per familyID and block count, as bootloaders ignore other families. */
  #number(familyId: number | null, declared: number, blockNo: number): void {
    if (declared === 0 || blockNo >= declared) {
      this.#outOfRange += 1;
      return;
    }
    const key = `${familyId === null ? "none" : String(familyId)}:${String(declared)}`;
    let sequence = this.#sequences.get(key);
    if (sequence === undefined) {
      sequence = { familyId, declared, seen: new Set(), previous: -1 };
      this.#sequences.set(key, sequence);
    }
    if (sequence.seen.has(blockNo)) this.#repeated += 1;
    else sequence.seen.add(blockNo);
    if (blockNo <= sequence.previous) this.#outOfOrder += 1;
    sequence.previous = blockNo;
  }

  #addData(
    block: number,
    familyId: number | null,
    address: number,
    data: Uint8Array,
  ): Result<void, Uf2Failure> {
    if (data.length === 0) return ok(undefined);
    const run = this.#runs.at(-1);
    if (
      run !== undefined &&
      run.familyId === familyId &&
      run.address + run.length === address
    ) {
      run.length += data.length;
      run.blockCount += 1;
      run.lastBlock = block;
    } else {
      if (this.#runs.length >= UF2_MAX_RUNS)
        return err({
          kind: "limit",
          boundary: "capacity",
          message: `block ${String(block)}: payloads start more than ${String(UF2_MAX_RUNS)} address-discontiguous block runs`,
        });
      this.#runs.push({
        familyId,
        address,
        offset: this.#arenaUsed,
        length: data.length,
        blockCount: 1,
        firstBlock: block,
        lastBlock: block,
      });
    }
    this.#arena.set(data, this.#arenaUsed);
    this.#arenaUsed += data.length;
    return ok(undefined);
  }

  #missing(): { readonly count: number; readonly named: string[] } {
    let count = 0;
    const named: string[] = [];
    for (const sequence of this.#sequences.values()) {
      const absent = sequence.declared - sequence.seen.size;
      if (absent === 0) continue;
      count += absent;
      named.push(
        `${familyText(sequence.familyId)} has ${String(sequence.seen.size)} of ${String(sequence.declared)} numbered blocks`,
      );
    }
    return { count, named };
  }

  /** Limitations that leave coverage unknown, then facts that do not. */
  #limitations(): { readonly unknown: string[]; readonly known: string[] } {
    const unknown: string[] = [];
    const known: string[] = [];
    if (this.#blockLength > 0)
      unknown.push(
        `UF2 file ends with ${String(this.#blockLength)} bytes after its last complete 512-byte block; the file may be truncated.`,
      );
    if (this.#firstInvalid !== undefined)
      unknown.push(
        `${String(this.#invalid)} UF2 block(s) are invalid and were excluded; the first is block ${String(this.#firstInvalid.block)} at byte offset ${String(this.#firstInvalid.block * UF2_BLOCK_BYTES)}: ${this.#firstInvalid.reason}.`,
      );
    const missing = this.#missing();
    if (missing.count > 0)
      unknown.push(
        `UF2 numbering declares ${String(missing.count)} block(s) that are absent: ${missing.named.slice(0, NAMED_SEQUENCES).join("; ")}${missing.named.length > NAMED_SEQUENCES ? `; and ${String(missing.named.length - NAMED_SEQUENCES)} more sequence(s)` : ""}.`,
      );
    if (this.#outOfRange > 0)
      unknown.push(
        `${String(this.#outOfRange)} UF2 block(s) have a block number at or above their block count, so their numbering cannot establish completeness.`,
      );
    if (this.#fileContainer > 0)
      unknown.push(
        `${String(this.#fileContainer)} UF2 block(s) belong to file containers (flag 0x1000); their files were not reconstructed.`,
      );
    if (this.#notMainFlash > 0)
      known.push(
        `${String(this.#notMainFlash)} UF2 block(s) are flagged not main flash (flag 0x1); their ${String(this.#notMainFlashBytes)} payload bytes are in no region.`,
      );
    return { unknown, known };
  }

  #metadata(
    regions: readonly Uf2Region[],
    duplicateBytes: number,
  ): Uf2Metadata {
    return {
      kind: "uf2",
      block_count: this.#blockCount,
      trailing_bytes: this.#blockLength,
      invalid_block_count: this.#invalid,
      flash_block_count: this.#flash,
      not_main_flash_block_count: this.#notMainFlash,
      file_container_block_count: this.#fileContainer,
      md5_block_count: this.#md5,
      extension_tag_block_count: this.#extensionTags,
      family_count: this.#families.size,
      sequence_count: this.#sequences.size,
      missing_block_count: this.#missing().count,
      repeated_block_count: this.#repeated,
      out_of_order_block_count: this.#outOfOrder,
      block_number_out_of_range_count: this.#outOfRange,
      region_count: regions.length,
      data_bytes: regions.reduce((sum, region) => sum + region.bytes.length, 0),
      duplicate_bytes: duplicateBytes,
    };
  }
}

const blockSpan = (run: BlockRun): string =>
  run.firstBlock === run.lastBlock
    ? `block ${String(run.firstBlock)}`
    : `blocks ${String(run.firstBlock)}-${String(run.lastBlock)}`;

/** Merge each family's runs by address; overlaps must repeat the same bytes. */
const mergeRuns = (
  runs: readonly BlockRun[],
  arena: Uint8Array,
): Result<
  { readonly regions: Uf2Region[]; readonly duplicateBytes: number },
  Uf2Failure
> => {
  // Undeclared families sort first; other families never merge with them.
  const merged = mergeArenaRuns(runs, arena, (run) => run.familyId ?? -1);
  if (!merged.ok) return err(conflict(merged.error));
  return ok({
    regions: merged.value.ranges.map(({ start, bytes, runs: group }) => ({
      familyId: group[0]?.familyId ?? null,
      start,
      end: start + bytes.length - 1,
      bytes,
      blockCount: group.reduce((sum, run) => sum + run.blockCount, 0),
      firstBlock: group.reduce(
        (block, run) => Math.min(block, run.firstBlock),
        Number.MAX_SAFE_INTEGER,
      ),
      lastBlock: group.reduce(
        (block, run) => Math.max(block, run.lastBlock),
        0,
      ),
    })),
    duplicateBytes: merged.value.duplicateBytes,
  });
};

const conflict = ({
  address,
  writer,
  run,
  existing,
  incoming,
}: RunConflict<BlockRun>): Uf2Failure => ({
  kind: "format",
  message: `${familyText(run.familyId)} address ${hex32(address)} is written with different values by ${blockSpan(writer)} (0x${existing.toString(16).padStart(2, "0")}) and ${blockSpan(run)} (0x${incoming.toString(16).padStart(2, "0")})`,
});
