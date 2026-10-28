import { z } from "zod";

import type { BinaryArchitecture } from "./binaryTargetTypes.js";

/**
 * How `open_binary` admits a file: as an executable for an analysis provider,
 * an analysis database, an archive whose entries are inventoried, or a single
 * artifact.
 */
export const TARGET_KINDS = [
  "executable",
  "database",
  "archive",
  "artifact",
] as const;
export type TargetKind = (typeof TARGET_KINDS)[number];

/**
 * Families an executable's header can declare: the ELF families, the Mach-O
 * families, or the four families other headers carry.
 */
export type HeaderArchitectureRule = "elf" | "mach-o" | "header";

/** Architecture an executable records because its header does not declare one. */
type DeclaredArchitecture =
  | "caller-selected"
  | { readonly fixed: BinaryArchitecture };

/** Independent load-image verification, one native load-image variant each. */
export type TargetLoadImageVariant = "dos" | "raw" | "dol";

interface TargetFormatFacts {
  readonly id: string;
  /** Artifact-graph role: a content-addressed node, or an occurrence classification only. */
  readonly artifactGraph?: "node" | "occurrence";
}

interface ExecutableFacts extends TargetFormatFacts {
  readonly target: "executable";
  /** Admitted only by explicit caller selection; the bytes carry no identifying header. */
  readonly selectable?: true;
  readonly loadImage?: TargetLoadImageVariant;
  readonly zipPackage?: never;
}

/** Facts one format owns; every vocabulary that names formats derives from them. */
type TargetFormatRow =
  | (ExecutableFacts & {
      readonly architecture: HeaderArchitectureRule;
      /** Meaning of the canonical entry address recorded with the target. */
      readonly entryPoint?: string;
    })
  | (ExecutableFacts & {
      /**
       * The caller's raw selection, or the one family the format fixes. The
       * header does not supply it, so the target records it with its entry.
       */
      readonly architecture: DeclaredArchitecture;
      readonly entryPoint: string;
    })
  | (TargetFormatFacts & {
      /** Kind `open_binary` admits; absent when only artifact inventory and Evidence name the format. */
      readonly target?: Exclude<TargetKind, "executable">;
      /** ZIP-backed application package that the shared ZIP reader inventories. */
      readonly zipPackage?: true;
      readonly architecture?: never;
      readonly entryPoint?: never;
      readonly selectable?: never;
      readonly loadImage?: never;
    });

/**
 * One row per format, in the order clients receive Evidence subject formats.
 * Append new formats: every derived enum keeps this order.
 */
export const TARGET_FORMATS = [
  { id: "hopper", artifactGraph: "occurrence" },
  {
    id: "analysis-database",
    target: "database",
    artifactGraph: "occurrence",
  },
  {
    id: "mach-o",
    target: "executable",
    architecture: "mach-o",
    artifactGraph: "node",
  },
  {
    id: "elf",
    target: "executable",
    architecture: "elf",
    artifactGraph: "node",
  },
  {
    id: "pe",
    target: "executable",
    architecture: "header",
    artifactGraph: "node",
  },
  {
    id: "dos-mz",
    target: "executable",
    architecture: "header",
    loadImage: "dos",
    artifactGraph: "node",
  },
  {
    id: "dos-com",
    target: "executable",
    architecture: "header",
    selectable: true,
    loadImage: "dos",
    artifactGraph: "occurrence",
  },
  {
    id: "raw-binary",
    target: "executable",
    architecture: "caller-selected",
    entryPoint:
      "Canonical caller-selected address where raw file offset 0 is mapped and execution is seeded.",
    selectable: true,
    loadImage: "raw",
    artifactGraph: "occurrence",
  },
  {
    id: "gamecube-dol",
    target: "executable",
    architecture: { fixed: "powerpc" },
    entryPoint:
      "Canonical entry address taken from the caller-selected DOL header.",
    selectable: true,
    loadImage: "dol",
    artifactGraph: "occurrence",
  },
  { id: "zip", target: "archive", zipPackage: true, artifactGraph: "node" },
  {
    id: "ipa",
    target: "archive",
    zipPackage: true,
    artifactGraph: "occurrence",
  },
  {
    id: "apk",
    target: "archive",
    zipPackage: true,
    artifactGraph: "occurrence",
  },
  {
    id: "msix",
    target: "archive",
    zipPackage: true,
    artifactGraph: "occurrence",
  },
  {
    id: "appx",
    target: "archive",
    zipPackage: true,
    artifactGraph: "occurrence",
  },
  {
    id: "hap",
    target: "archive",
    zipPackage: true,
    artifactGraph: "occurrence",
  },
  {
    id: "hsp",
    target: "archive",
    zipPackage: true,
    artifactGraph: "occurrence",
  },
  {
    id: "app-pack",
    target: "archive",
    zipPackage: true,
    artifactGraph: "occurrence",
  },
  { id: "asar", target: "archive", artifactGraph: "occurrence" },
  { id: "godot-pck", target: "archive", artifactGraph: "node" },
  { id: "unityfs", target: "archive", artifactGraph: "node" },
  { id: "uimage", target: "archive", artifactGraph: "node" },
  { id: "dmg", target: "archive", artifactGraph: "occurrence" },
  { id: "pkg", target: "archive", artifactGraph: "occurrence" },
  { id: "plist", target: "artifact", artifactGraph: "node" },
  // The artifact graph names JavaScript files `javascript-bundle`.
  { id: "javascript", target: "artifact" },
  { id: "source-map", target: "artifact", artifactGraph: "occurrence" },
  { id: "directory", artifactGraph: "node" },
  { id: "file", artifactGraph: "node" },
  { id: "unknown", artifactGraph: "node" },
  {
    id: "mach-o-universal",
    target: "executable",
    architecture: "header",
    artifactGraph: "node",
  },
  { id: "javascript-bundle", artifactGraph: "occurrence" },
  { id: "entitlements", artifactGraph: "occurrence" },
  { id: "pyinstaller", artifactGraph: "occurrence" },
  { id: "node-sea", artifactGraph: "occurrence" },
  { id: "intel-hex", target: "archive", artifactGraph: "node" },
  { id: "srec", target: "archive", artifactGraph: "node" },
] as const satisfies readonly TargetFormatRow[];

type Row = (typeof TARGET_FORMATS)[number];
type SelectableKey = Exclude<keyof TargetFormatRow, "id">;
/** Primitive facts only: rows are matched by identity, not structure. */
type SelectableValue<Key extends SelectableKey> = Exclude<
  NonNullable<TargetFormatRow[Key]>,
  object
>;
/** Rows whose `Key` holds one of `Value`, exactly as {@link targetFormatRows} matches. */
type TargetFormatRowWith<Key extends SelectableKey, Value> = Extract<
  Row,
  { readonly [Field in Key]: Value }
>;

/** Every format an Evidence subject can name. */
type TargetFormat = Row["id"];
/** Formats `open_binary` admits as one of the given kinds. */
export type TargetFormatOfKind<Kind extends TargetKind = TargetKind> =
  TargetFormatRowWith<"target", Kind>["id"];

/** Every format id, in table order. */
export const TARGET_FORMAT_IDS: readonly TargetFormat[] = TARGET_FORMATS.map(
  (row) => row.id,
);

const rowId = <R extends Row>(row: R): R["id"] => row.id;

/** Rows whose `key` holds one of `values`, in table order. */
const targetFormatRows = <
  const Key extends SelectableKey,
  const Value extends SelectableValue<Key>,
>(
  key: Key,
  ...values: readonly Value[]
): readonly TargetFormatRowWith<Key, Value>[] =>
  TARGET_FORMATS.filter((row): row is TargetFormatRowWith<Key, Value> =>
    values.some((value) => (row as TargetFormatRow)[key] === value),
  );

/** Ids of the rows {@link targetFormatRows} selects. */
export const targetFormatIds = <
  const Key extends SelectableKey,
  const Value extends SelectableValue<Key>,
>(
  key: Key,
  ...values: readonly Value[]
): readonly TargetFormatRowWith<Key, Value>["id"][] =>
  targetFormatRows(key, ...values).map(rowId);

/** The facts a format id names, or undefined for an unknown spelling. */
export const targetFormatRow = (format: string): TargetFormatRow | undefined =>
  TARGET_FORMATS.find((row) => row.id === format);

/** Whether `open_binary` admits `format` as the given kind. */
export const isTargetFormatOfKind = <Kind extends TargetKind>(
  format: string,
  kind: Kind,
): format is TargetFormatOfKind<Kind> =>
  targetFormatRow(format)?.target === kind;

type DeclaredArchitectureRow = Extract<
  Row,
  { readonly architecture: DeclaredArchitecture }
>;
const declaresArchitecture = (
  row: TargetFormatRow,
): row is DeclaredArchitectureRow =>
  row.architecture === "caller-selected" ||
  typeof row.architecture === "object";
/** Executables whose header does not supply the architecture they persist. */
export const DECLARED_ARCHITECTURE_ROWS: readonly DeclaredArchitectureRow[] =
  TARGET_FORMATS.filter(declaresArchitecture);

type EntryPointRow = Extract<Row, { readonly entryPoint: string }>;
/** Targets that record a canonical entry address with their identity. */
export const ENTRY_POINT_ROWS: readonly EntryPointRow[] = TARGET_FORMATS.filter(
  (row): row is EntryPointRow => "entryPoint" in row,
);

/** A single format as a literal and several as an enum, as schemas have always published them. */
export const targetFormatSchema = <const Id extends TargetFormat>(
  ids: readonly Id[],
) => (ids.length === 1 ? z.literal(ids[0]!) : z.enum(ids));

/**
 * Keep an enum order clients already receive. Pinned ids come first; members
 * added later follow in table order, so a new row never edits a pin.
 */
export const inPublishedOrder = <Id extends string>(
  members: readonly Id[],
  published: readonly NoInfer<Id>[],
): readonly Id[] => [
  ...published.filter((id) => members.includes(id)),
  ...members.filter((id) => !published.includes(id)),
];
