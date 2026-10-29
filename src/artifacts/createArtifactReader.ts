import type { ArtifactReaderAdmission } from "./ArtifactReaderAdmission.js";
import type { AsarHeaderAdmission } from "../config/asarHeaderAdmission.js";
import { DotnetBundleArtifactReader } from "./DotnetBundleArtifactReader.js";
import { AsarArtifactReader } from "./AsarArtifactReader.js";
import type { ArtifactReader } from "./ArtifactReader.js";
import { HexRecordArtifactReader } from "./HexRecordArtifactReader.js";
import { Uf2ArtifactReader } from "./Uf2ArtifactReader.js";
import { DfuSeArtifactReader } from "./DfuSeArtifactReader.js";
import { DirectoryArtifactReader } from "./DirectoryArtifactReader.js";
import { EspImageArtifactReader } from "./EspImageArtifactReader.js";
import { EspFlashImageArtifactReader } from "./EspFlashImageArtifactReader.js";
import type { EspFlashSelection } from "../domain/firmware/espFlashLocation.js";
import { FitArtifactReader } from "./FitArtifactReader.js";
import { GodotPckArtifactReader } from "./GodotPckArtifactReader.js";
import { MachOSliceArtifactReader } from "./MachOSliceArtifactReader.js";
import { NativeDmgArtifactReader } from "./NativeDmgArtifactReader.js";
import { NodeSeaArtifactReader } from "./NodeSeaArtifactReader.js";
import { PyInstallerArtifactReader } from "./PyInstallerArtifactReader.js";
import { UImageArtifactReader } from "./UImageArtifactReader.js";
import { UnityFsArtifactReader } from "./UnityFsArtifactReader.js";
import { ZipArtifactReader } from "./ZipArtifactReader.js";
import type { ArtifactOccurrence } from "../domain/artifactGraph.js";
import {
  isZipPackageFormat,
  type ZipPackageFormat,
} from "../domain/zipPackageFormat.js";

/** Formats with an artifact entry reader; availability policy belongs to the caller. */
export type ArtifactReaderFormat =
  | "directory"
  | "asar"
  | "pyinstaller"
  | "node-sea"
  | "dotnet-bundle"
  | "godot-pck"
  | "unityfs"
  | "uimage"
  | "intel-hex"
  | "srec"
  | "uf2"
  | "dfuse"
  | "fit"
  | "mach-o-universal"
  | "dmg"
  | "esp-image"
  | "esp-flash-image"
  | ZipPackageFormat;

interface ArtifactReaderConstruction {
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly unreadableDirectories: "fail" | "omit";
  readonly admission?: ArtifactReaderAdmission | undefined;
  readonly asarHeaderAdmission?: AsarHeaderAdmission | undefined;
  /** Caller inputs for an explicitly selected ESP flash image. */
  readonly espFlashSelection?: EspFlashSelection | undefined;
  /** Caller-selected root spelling; only ASAR companion lookup consumes this. */
  readonly selectedPath?: string | undefined;
}

export function createArtifactReader(
  path: string,
  format: ArtifactReaderFormat,
  options: ArtifactReaderConstruction,
): ArtifactReader;
export function createArtifactReader(
  path: string,
  format: ArtifactOccurrence["artifact_format"],
  options: ArtifactReaderConstruction,
): ArtifactReader | undefined;
/** Construct a reader without acquiring or transferring its source ownership. */
export function createArtifactReader(
  path: string,
  format: ArtifactOccurrence["artifact_format"],
  options: ArtifactReaderConstruction,
): ArtifactReader | undefined {
  const admission = options.admission;
  const rootSource =
    admission !== undefined && "kind" in admission
      ? admission.source
      : admission;
  if (isZipPackageFormat(format))
    return new ZipArtifactReader(path, format, undefined, rootSource);
  switch (format) {
    case "directory":
      return new DirectoryArtifactReader(path, options.unreadableDirectories);
    case "asar":
      return new AsarArtifactReader(path, {
        ...(options.asarHeaderAdmission === undefined
          ? {}
          : { headerAdmission: options.asarHeaderAdmission }),
        ...(options.selectedPath === undefined
          ? {}
          : { selectedPath: options.selectedPath }),
      });
    case "pyinstaller":
      return new PyInstallerArtifactReader(
        path,
        admission !== undefined &&
          "kind" in admission &&
          admission.kind === "pyinstaller"
          ? admission
          : rootSource,
      );
    case "dotnet-bundle":
      return new DotnetBundleArtifactReader(
        path,
        admission !== undefined &&
          "kind" in admission &&
          admission.kind === "dotnet-bundle"
          ? admission
          : rootSource,
      );
    case "node-sea":
      return new NodeSeaArtifactReader(
        path,
        admission !== undefined &&
          "kind" in admission &&
          admission.kind === "node-sea"
          ? admission
          : rootSource,
      );
    case "godot-pck":
      return new GodotPckArtifactReader(
        path,
        admission !== undefined &&
          "kind" in admission &&
          admission.kind === "godot-pck"
          ? admission
          : rootSource,
      );
    case "uimage":
      return new UImageArtifactReader(path, rootSource);
    case "unityfs":
      return new UnityFsArtifactReader(path, rootSource);
    case "intel-hex":
    case "srec":
      return new HexRecordArtifactReader(path, format, rootSource);
    case "uf2":
      return new Uf2ArtifactReader(path, rootSource);
    case "dfuse":
      return new DfuSeArtifactReader(path, rootSource);
    case "fit":
      return new FitArtifactReader(path, rootSource);
    case "mach-o-universal":
      return new MachOSliceArtifactReader(
        path,
        options.environment,
        undefined,
        rootSource,
      );
    case "dmg":
      return new NativeDmgArtifactReader(path, options.environment);
    case "esp-image":
      return new EspImageArtifactReader(path, rootSource);
    case "esp-flash-image":
      return new EspFlashImageArtifactReader(
        path,
        admission !== undefined &&
          "kind" in admission &&
          admission.kind === "esp-flash-image"
          ? admission
          : rootSource,
        options.espFlashSelection,
      );
    default:
      return undefined;
  }
}
