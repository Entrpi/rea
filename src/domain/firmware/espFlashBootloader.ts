import {
  ESP_ROM_BOOTLOADER_OFFSETS,
  espChipForId,
  type EspChip,
} from "./espChips.js";
import { recognizeEspImage } from "./espImage.js";
import { offsetText, u16 } from "./espImageStructures.js";

/** Bytes that recognition needs at a candidate bootloader offset. */
export const ESP_BOOTLOADER_PROBE_BYTES = 32;

/** Where the dump holds bytes for each ROM bootloader offset. */
export interface EspBootloaderProbe {
  /** Flash address the ROM loads from. */
  readonly flashAddress: number;
  /** The same address in the file, given the dump's flash offset. */
  readonly fileOffset: number;
  /** Up to `ESP_BOOTLOADER_PROBE_BYTES` from that file offset. */
  readonly prefix: Uint8Array;
  /** Bytes from that file offset to the end of the file. */
  readonly available: number;
}

export interface EspBootloaderLocation {
  readonly flashAddress: number;
  readonly fileOffset: number;
  readonly chip: EspChip;
}

/**
 * The bootloader is the ESP image at the flash address its chip's ROM loads
 * from (`ESP_ROM_BOOTLOADER_OFFSET_FLASH`). An image at another chip's ROM
 * offset is reported, not located: the dump may not start where its flash
 * offset says.
 */
export const locateEspBootloader = (
  probes: readonly EspBootloaderProbe[],
): {
  readonly location: EspBootloaderLocation | undefined;
  readonly limitations: readonly string[];
} => {
  const limitations: string[] = [];
  for (const probe of probes) {
    if (recognizeEspImage(probe.prefix, probe.available) !== "esp-image")
      continue;
    const chipId = u16(probe.prefix, 12);
    const chip = espChipForId(chipId);
    if (chip?.romBootloaderOffset === probe.flashAddress)
      return {
        location: {
          flashAddress: probe.flashAddress,
          fileOffset: probe.fileOffset,
          chip,
        },
        limitations: [],
      };
    limitations.push(
      chip === undefined
        ? `An ESP image at flash ${offsetText(probe.flashAddress)} has chip_id 0x${chipId.toString(16).padStart(4, "0")}, which is not in the chip table; it is not read as the bootloader.`
        : `An ${chip.target} image is at flash ${offsetText(probe.flashAddress)}, but its ROM loads the bootloader from ${offsetText(chip.romBootloaderOffset)}; the dump may not start at the given flash offset.`,
    );
  }
  return { location: undefined, limitations };
};

/** The file offsets that hold each ROM bootloader offset, given the dump's origin. */
export const espBootloaderProbeOffsets = (
  flashOffset: number,
  fileSize: number,
): readonly { readonly flashAddress: number; readonly fileOffset: number }[] =>
  ESP_ROM_BOOTLOADER_OFFSETS.map((flashAddress) => ({
    flashAddress,
    fileOffset: flashAddress - flashOffset,
  })).filter(({ fileOffset }) => fileOffset >= 0 && fileOffset < fileSize);
