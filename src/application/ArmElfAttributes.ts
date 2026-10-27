import type { FileHandle } from "node:fs/promises";

import {
  ARM_BUILD_ATTRIBUTES_MAX_BYTES,
  parseArmBuildAttributes,
} from "../domain/armBuildAttributes.js";
import type {
  ArmElfAttributesObservation,
  ArmElfMetadata,
} from "../domain/binaryTargetTypes.js";
import { readElfFixedHeader } from "../domain/elfFixedHeader.js";
import { readElfRawTableDeclarations } from "../domain/elfRawTableDeclarations.js";
import { readElfSectionHeader } from "../domain/elfSectionHeader.js";
import { err, ok, type Result } from "../domain/result.js";

const EM_ARM = 40;
const SHT_ARM_ATTRIBUTES = 0x70000003;
const SECTION_HEADER_BYTES = 40;
/** Section headers per read, so a large table is never held at once. */
const HEADERS_PER_READ = Math.floor((64 * 1024) / SECTION_HEADER_BYTES);

type ReadRange = (
  offset: number,
  length: number,
  label: string,
) => Promise<Result<Buffer, string>>;

/** Read exactly `length` bytes, failing when the file has shrunk since resolution. */
const rangeReader =
  (handle: FileHandle, checkCancelled: () => void): ReadRange =>
  async (offset, length, label) => {
    const bytes = Buffer.alloc(length);
    let total = 0;
    while (total < length) {
      checkCancelled();
      const observed = await handle.read(
        bytes,
        total,
        length - total,
        offset + total,
      );
      checkCancelled();
      if (observed.bytesRead === 0)
        return err(`the ARM ${label} is shorter than when it was resolved`);
      total += observed.bytesRead;
    }
    return ok(bytes);
  };

/** The one attributes section, its absence, or more than one. */
const findAttributesSection = async (
  read: ReadRange,
  sections: { readonly offset: bigint; readonly count: number },
  little: boolean,
): Promise<
  Result<
    { readonly offset: number; readonly size: number } | "absent" | "ambiguous",
    string
  >
> => {
  let found: { readonly offset: number; readonly size: number } | undefined;
  // The resolver has already checked that the table and every section lie in the file.
  for (let first = 0; first < sections.count; first += HEADERS_PER_READ) {
    const count = Math.min(HEADERS_PER_READ, sections.count - first);
    const table = await read(
      Number(sections.offset) + first * SECTION_HEADER_BYTES,
      count * SECTION_HEADER_BYTES,
      "section header table",
    );
    if (!table.ok) return table;
    for (let index = 0; index < count; index += 1) {
      const at = index * SECTION_HEADER_BYTES;
      const section = readElfSectionHeader(
        table.value.subarray(at, at + SECTION_HEADER_BYTES),
        32,
        little,
      );
      if (!section.ok) return err(section.error.message);
      if (section.value.type !== SHT_ARM_ATTRIBUTES) continue;
      if (found !== undefined) return ok("ambiguous");
      found = {
        offset: Number(section.value.offset),
        size: Number(section.value.size),
      };
    }
  }
  return ok(found ?? "absent");
};

/**
 * Read the `.ARM.attributes` declarations of an ELF32 ARM file from the
 * caller's open handle, finding the section by type rather than by name.
 * Every ARM ELF loaded before REA read these declarations, so a missing
 * section is an observed absence, and a section REA cannot read leaves them
 * unknown; neither fails resolution. A file that changes while it is read
 * does. The caller supplies its cancellation check so its tagged error is
 * preserved.
 */
export const readArmElfAttributes = async (
  handle: FileHandle,
  metadata: ArmElfMetadata,
  checkCancelled: () => void,
): Promise<Result<ArmElfAttributesObservation, string>> => {
  checkCancelled();
  const read = rangeReader(handle, checkCancelled);
  const unavailable = (
    reason: string,
  ): Result<ArmElfAttributesObservation, string> =>
    ok({ status: "unavailable", reason });

  const fileSize = (await handle.stat()).size;
  checkCancelled();
  const header = await read(0, 52, "ELF header");
  if (!header.ok) return header;
  const fixed = readElfFixedHeader(header.value, fileSize);
  if (
    !fixed.ok ||
    fixed.value.machine !== EM_ARM ||
    fixed.value.elfClass !== metadata.elfClass ||
    fixed.value.byteOrder !== metadata.byteOrder ||
    fixed.value.type !== metadata.type ||
    fixed.value.flags !== metadata.flags
  )
    return err("the ARM ELF header no longer matches the resolved identity");
  const declarations = readElfRawTableDeclarations(header.value, fixed.value);
  if (!declarations.ok) return err(declarations.error.message);
  const { sections } = declarations.value;
  if (sections.count === 0)
    return unavailable(
      sections.offset === 0n
        ? "the image has no section header table"
        : "extended section numbering is not read",
    );
  if (sections.width !== SECTION_HEADER_BYTES)
    return unavailable(
      `the section header size is ${sections.width}, not ${SECTION_HEADER_BYTES}`,
    );
  const little = metadata.byteOrder === "little";
  const found = await findAttributesSection(read, sections, little);
  if (!found.ok) return found;
  if (found.value === "absent") return ok({ status: "absent" });
  if (found.value === "ambiguous")
    return unavailable("the image has more than one attributes section");
  const { offset, size } = found.value;
  if (size === 0 || size > ARM_BUILD_ATTRIBUTES_MAX_BYTES)
    return unavailable(
      `the attributes section has ${size} bytes, outside the read bound of 1 to ${ARM_BUILD_ATTRIBUTES_MAX_BYTES}`,
    );
  const payload = await read(offset, size, "attributes section");
  if (!payload.ok) return payload;
  const parsed = parseArmBuildAttributes(payload.value, little);
  return parsed.ok
    ? ok({ status: "declared", declarations: parsed.value })
    : unavailable(parsed.error);
};
