import { compareUnicodeCodePoints } from "./unicodeCodePointOrder.js";
import { z } from "zod";

import type {
  ArtifactInventoryResult,
  ArtifactNode,
  ArtifactOccurrence,
} from "./artifactGraph.js";
import { AnalysisInputError } from "./analysisErrorCore.js";
import { evidenceSchema } from "./evidence.js";
import {
  ArtifactInventoryCarrierError,
  hasCompleteInventoryCoverage,
  parseArtifactInventoryEvidence,
  type InventorySet,
} from "./artifactInventoryEvidence.js";
import {
  formatMetadataDeclaration,
  type FormatMetadataDeclaration,
} from "./artifactFormatMetadata.js";
import { prefixedDigestSchema } from "./../domain/digests.js";
import { canonicalJson } from "./comparisonSemantics.js";

const evidenceIdSchema = prefixedDigestSchema("ev");
const comparisonStatusSchema = z.enum([
  "unchanged",
  "added",
  "removed",
  "changed",
  "truncated",
  "unknown",
  "contradiction",
]);
const changeKindSchema = z.enum([
  "added",
  "removed",
  "changed",
  "unknown",
  "contradiction",
]);
const comparisonDimensionSchema = z.enum([
  "content",
  "kind",
  "format",
  "size",
  "executable",
  "relations",
  "metadata",
  "availability",
  "integrity",
]);
/** Strict Evidence-backed input for deterministic artifact comparison. */
export const artifactComparisonInputSchema = z.strictObject({
  left: evidenceSchema,
  right: evidenceSchema,
});

/** One path-classified artifact change with citations to both observations. */
const artifactChangeSchema = z.object({
  classification: changeKindSchema,
  logical_path: z.string().min(1),
  dimensions: z.array(comparisonDimensionSchema).min(1),
  left_occurrence_id: z
    .string()
    .regex(/^occ_[a-f0-9]{64}$/u)
    .nullable(),
  right_occurrence_id: z
    .string()
    .regex(/^occ_[a-f0-9]{64}$/u)
    .nullable(),
  left_artifact_id: z
    .string()
    .regex(/^art_[a-f0-9]{64}$/u)
    .nullable(),
  right_artifact_id: z
    .string()
    .regex(/^art_[a-f0-9]{64}$/u)
    .nullable(),
  evidence_links: z.array(evidenceIdSchema).min(2),
});

/** Deterministic artifact comparison with every change returned inline. */
export const artifactComparisonResultSchema = z.object({
  status: comparisonStatusSchema,
  left_manifest_id: prefixedDigestSchema("agm"),
  right_manifest_id: prefixedDigestSchema("agm"),
  summary: z.object({
    unchanged: z.int().min(0),
    added: z.int().min(0),
    removed: z.int().min(0),
    changed: z.int().min(0),
    unknown: z.int().min(0),
    contradiction: z.int().min(0).default(0),
  }),
  changes: z.array(artifactChangeSchema),
  // Absent on legacy records; absence does not identify a contradicting side.
  integrity_mismatch_evidence_ids: z.array(evidenceIdSchema).optional(),
  limitations: z.array(z.string()),
});

export type ArtifactComparisonResult = z.infer<
  typeof artifactComparisonResultSchema
>;
type ArtifactChange = z.infer<typeof artifactChangeSchema>;

/** Comparison limitation when a path's format declarations cannot be compared. */
export const FORMAT_DECLARATION_UNKNOWN_LIMITATION =
  "Format metadata declarations are missing on one side or differ in kind for matching paths; omitted metadata may be a legacy or non-container observation and leaves the complete declaration unavailable.";

const comparisonInventory = (input: unknown, side: "left" | "right") => {
  try {
    return parseArtifactInventoryEvidence(input);
  } catch (cause: unknown) {
    if (!(cause instanceof ArtifactInventoryCarrierError)) throw cause;
    throw new AnalysisInputError(
      "compare_artifacts",
      { cause, userMessage: cause.message },
      [{ path: [side], reason: "invalid_value", message: cause.message }],
    );
  }
};

/** Compare complete inventory evidence without treating missing evidence as equality. */
export const compareArtifacts = (
  leftEvidence: unknown,
  rightEvidence: unknown,
): ArtifactComparisonResult => {
  const left = comparisonInventory(leftEvidence, "left");
  const right = comparisonInventory(rightEvidence, "right");
  const leftComplete = left.inventory.complete;
  const rightComplete = right.inventory.complete;
  const sameScope =
    left.inventory.coverage.scope === right.inventory.coverage.scope;
  const rootCoverageComplete =
    sameScope &&
    left.inventory.complete &&
    right.inventory.complete &&
    left.inventory.coverage.status === "complete" &&
    right.inventory.coverage.status === "complete";
  const entryCoverageComplete =
    rootCoverageComplete &&
    left.inventory.coverage.scope === "container-entries";
  const leftCovered =
    sameScope &&
    hasCompleteInventoryCoverage(left.inventory, left.inventory.coverage.scope);
  const rightCovered =
    sameScope &&
    hasCompleteInventoryCoverage(
      right.inventory,
      right.inventory.coverage.scope,
    );
  const fullyCovered =
    leftCovered &&
    rightCovered &&
    (entryCoverageComplete ||
      (rootCoverageComplete &&
        left.inventory.manifest.occurrence_count === 1 &&
        right.inventory.manifest.occurrence_count === 1));
  const leftOccurrencesByPath = occurrencesByPath(left.inventory.occurrences);
  const rightOccurrencesByPath = occurrencesByPath(right.inventory.occurrences);
  const comparison = compareOccurrences(
    left.inventory,
    right.inventory,
    leftOccurrencesByPath,
    rightOccurrencesByPath,
    [
      ...left.evidence.map(({ evidence_id: id }) => id),
      ...right.evidence.map(({ evidence_id: id }) => id),
    ],
    { root: rootCoverageComplete, entries: entryCoverageComplete },
  );
  const changes = comparison.changes;
  const limitations = [
    ...left.inventory.limitations.map((item) => `Left: ${item}`),
    ...right.inventory.limitations.map((item) => `Right: ${item}`),
    ...(leftComplete ? [] : ["Left artifact inventory is incomplete."]),
    ...(rightComplete ? [] : ["Right artifact inventory is incomplete."]),
    ...(sameScope ? [] : ["Artifact inventory scopes differ."]),
    ...(sameScope &&
    left.inventory.coverage.scope === "root" &&
    (left.inventory.manifest.occurrence_count > 1 ||
      right.inventory.manifest.occurrence_count > 1)
      ? ["Container entry coverage is unavailable for child paths."]
      : []),
    ...(left.inventory.coverage.status === "complete"
      ? []
      : ["Left artifact inventory traversal coverage is unknown."]),
    ...(right.inventory.coverage.status === "complete"
      ? []
      : ["Right artifact inventory traversal coverage is unknown."]),
    ...(comparison.hasUnknownAsarPacking
      ? [
          "ASAR packing metadata is recorded on only one side for matching paths; omitted metadata may be a legacy observation and does not establish packed or unpacked storage.",
        ]
      : []),
    ...(comparison.hasUnknownFormatDeclaration
      ? [FORMAT_DECLARATION_UNKNOWN_LIMITATION]
      : []),
    ...(comparison.hasAmbiguousDuplicatePaths
      ? [
          "Duplicate logical paths cannot be paired across inventories; comparisons for those paths are unknown.",
        ]
      : []),
  ];
  applyRootHashChange(left.inventory, right.inventory, changes, [
    ...left.evidence.map(({ evidence_id: id }) => id),
    ...right.evidence.map(({ evidence_id: id }) => id),
  ]);
  const summary = summarize(
    left.inventory,
    right.inventory,
    changes,
    fullyCovered,
  );
  return artifactComparisonResultSchema.parse({
    status:
      !leftComplete || !rightComplete
        ? "truncated"
        : changes.some(
              ({ classification }) => classification === "contradiction",
            )
          ? "contradiction"
          : !fullyCovered
            ? "unknown"
            : changes.some(({ classification }) => classification === "unknown")
              ? "unknown"
              : changes.length === 0
                ? "unchanged"
                : "changed",
    left_manifest_id: left.inventory.manifest.manifest_id,
    right_manifest_id: right.inventory.manifest.manifest_id,
    summary,
    changes,
    integrity_mismatch_evidence_ids: [
      ...new Set(
        [left, right].flatMap((source) =>
          source.inventory.occurrences.some(
            (occurrence) => occurrence.hash_status === "mismatched",
          )
            ? source.evidence.map((record) => record.evidence_id)
            : [],
        ),
      ),
    ].sort(compareUnicodeCodePoints),
    limitations: [...new Set(limitations)].sort(compareUnicodeCodePoints),
  });
};

const compareOccurrences = (
  left: InventorySet,
  right: InventorySet,
  leftByPath: ReadonlyMap<string, ArtifactOccurrence[]>,
  rightByPath: ReadonlyMap<string, ArtifactOccurrence[]>,
  evidenceLinks: readonly string[],
  coverage: { readonly root: boolean; readonly entries: boolean },
): {
  readonly changes: ArtifactChange[];
  readonly hasAmbiguousDuplicatePaths: boolean;
  readonly hasUnknownAsarPacking: boolean;
  readonly hasUnknownFormatDeclaration: boolean;
} => {
  const leftNodes = new Map(left.nodes.map((item) => [item.artifact_id, item]));
  const rightNodes = new Map(
    right.nodes.map((item) => [item.artifact_id, item]),
  );
  const leftRelations = relationsByPath(left);
  const rightRelations = relationsByPath(right);
  const paths = [
    ...new Set([...leftByPath.keys(), ...rightByPath.keys()]),
  ].sort(compareUnicodeCodePoints);
  const output: ArtifactChange[] = [];
  let hasAmbiguousDuplicatePaths = false;
  let hasUnknownAsarPacking = false;
  let hasUnknownFormatDeclaration = false;
  for (const path of paths) {
    const leftMatches = leftByPath.get(path) ?? [];
    const rightMatches = rightByPath.get(path) ?? [];
    if (leftMatches.length > 1 || rightMatches.length > 1) {
      hasAmbiguousDuplicatePaths = true;
      output.push({
        logical_path: path,
        classification: "unknown",
        dimensions: ["availability"],
        left_occurrence_id: null,
        right_occurrence_id: null,
        left_artifact_id: null,
        right_artifact_id: null,
        evidence_links: [...evidenceLinks],
      });
      continue;
    }
    const leftOccurrence = leftMatches[0];
    const rightOccurrence = rightMatches[0];
    const metadata = occurrenceMetadata({ leftOccurrence, rightOccurrence });
    if (leftOccurrence !== undefined && rightOccurrence !== undefined) {
      if (metadata.asarPacking === "unknown") hasUnknownAsarPacking = true;
      if (metadata.formatDeclaration === "unknown")
        hasUnknownFormatDeclaration = true;
    }
    const change = classifyPath({
      metadata,
      path,
      leftOccurrence,
      rightOccurrence,
      leftNode: nodeFor(leftOccurrence, leftNodes),
      rightNode: nodeFor(rightOccurrence, rightNodes),
      leftRelations: leftRelations.get(path) ?? [],
      rightRelations: rightRelations.get(path) ?? [],
      rootCovered: coverage.root,
      entriesCovered: coverage.entries,
      evidenceLinks,
    });
    if (change !== null) output.push(change);
  }
  return {
    changes: output,
    hasAmbiguousDuplicatePaths,
    hasUnknownAsarPacking,
    hasUnknownFormatDeclaration,
  };
};

const occurrencesByPath = (
  occurrences: readonly ArtifactOccurrence[],
): ReadonlyMap<string, ArtifactOccurrence[]> => {
  const output = new Map<string, ArtifactOccurrence[]>();
  for (const occurrence of occurrences) {
    const matches = output.get(occurrence.logical_path);
    if (matches === undefined)
      output.set(occurrence.logical_path, [occurrence]);
    else matches.push(occurrence);
  }
  return output;
};

interface ClassifyPathInput {
  readonly metadata: OccurrenceMetadata;
  readonly path: string;
  readonly leftOccurrence: ArtifactOccurrence | undefined;
  readonly rightOccurrence: ArtifactOccurrence | undefined;
  readonly leftNode: ArtifactNode | undefined;
  readonly rightNode: ArtifactNode | undefined;
  readonly leftRelations: readonly RelationProjection[];
  readonly rightRelations: readonly RelationProjection[];
  readonly rootCovered: boolean;
  readonly entriesCovered: boolean;
  readonly evidenceLinks: readonly string[];
}

const buildArtifactChangeBase = (input: ClassifyPathInput) => ({
  logical_path: input.path,
  left_occurrence_id: input.leftOccurrence?.occurrence_id ?? null,
  right_occurrence_id: input.rightOccurrence?.occurrence_id ?? null,
  left_artifact_id: input.leftOccurrence?.artifact_id ?? null,
  right_artifact_id: input.rightOccurrence?.artifact_id ?? null,
  evidence_links: [...input.evidenceLinks],
});

const classifyPresence = (
  input: ClassifyPathInput,
  base: ReturnType<typeof buildArtifactChangeBase>,
): ArtifactChange | null => {
  const covered = input.path === "." ? input.rootCovered : input.entriesCovered;
  if (input.leftOccurrence === undefined)
    return {
      ...base,
      classification: covered ? "added" : "unknown",
      dimensions: [covered ? "content" : "availability"],
    };
  if (input.rightOccurrence === undefined)
    return {
      ...base,
      classification: covered ? "removed" : "unknown",
      dimensions: [covered ? "content" : "availability"],
    };
  return null;
};

const classifyIntegrity = (
  input: ClassifyPathInput,
  base: ReturnType<typeof buildArtifactChangeBase>,
): ArtifactChange | null => {
  if (
    input.leftOccurrence?.hash_status === "mismatched" ||
    input.rightOccurrence?.hash_status === "mismatched"
  )
    return {
      ...base,
      classification: "contradiction",
      dimensions: ["integrity"],
    };
  return null;
};

const classifyPath = (input: ClassifyPathInput): ArtifactChange | null => {
  const base = buildArtifactChangeBase(input);
  // A declared/observed mismatch is known even without an opposite occurrence.
  const integrity = classifyIntegrity(input, base);
  if (integrity !== null) return integrity;
  const presence = classifyPresence(input, base);
  if (presence !== null) return presence;
  const declared = declaredChecks(input);
  const unknown = declarationUnknown(input.metadata);
  if (isDeclarationRecord(input))
    return classifyChecks(base, declared, unknown);
  const left = input.leftNode;
  const right = input.rightNode;
  // Unless both sides have content, only the declared facts are known.
  if (
    input.leftOccurrence?.hash_status !== "verified" ||
    input.rightOccurrence?.hash_status !== "verified" ||
    left === undefined ||
    right === undefined
  )
    return classifyChecks(base, declared, true);
  return classifyChecks(
    base,
    [...declared, ...nodeChecks(input, left, right)],
    unknown,
  );
};

type ComparisonDimension = z.infer<typeof comparisonDimensionSchema>;
type DimensionCheck = readonly [ComparisonDimension, boolean];

/**
 * A known difference is a change, and an unknown fact adds availability.
 * Without a known difference, an unknown fact leaves the path unknown.
 */
const classifyChecks = (
  base: ReturnType<typeof buildArtifactChangeBase>,
  checks: readonly DimensionCheck[],
  unknown: boolean,
): ArtifactChange | null => {
  const dimensions = comparisonDimensionSchema.options.filter((dimension) =>
    checks.some(([checked, changed]) => changed && checked === dimension),
  );
  if (dimensions.length === 0)
    return unknown
      ? { ...base, classification: "unknown", dimensions: ["availability"] }
      : null;
  return {
    ...base,
    classification: "changed",
    dimensions: unknown ? [...dimensions, "availability"] : dimensions,
  };
};

type OccurrencePair = Pick<
  ClassifyPathInput,
  "leftOccurrence" | "rightOccurrence"
>;

type MetadataComparison = "unchanged" | "changed" | "unknown";
/** A field that every occurrence records, so a pair's comparison is known. */
type RequiredFieldComparison = Exclude<MetadataComparison, "unknown">;

interface OccurrenceMetadata {
  /** ASAR storage is an occurrence field, not format metadata. */
  readonly asarPacking: MetadataComparison;
  readonly encryption: RequiredFieldComparison;
  readonly entryKind: RequiredFieldComparison;
  /** Absent when neither occurrence records a compared declaration. */
  readonly formatDeclaration: MetadataComparison | "absent";
}

/** A declared fact that differs, known even when content is unavailable. */
const declarationChanged = (metadata: OccurrenceMetadata): boolean =>
  metadata.asarPacking === "changed" ||
  metadata.encryption === "changed" ||
  metadata.entryKind === "changed" ||
  metadata.formatDeclaration === "changed";

/** A declared fact that one side omits or records as another kind. */
const declarationUnknown = (metadata: OccurrenceMetadata): boolean =>
  Object.values(metadata).includes("unknown");

const compareAsarPacking = (
  left: boolean | undefined,
  right: boolean | undefined,
): MetadataComparison =>
  left === right
    ? "unchanged"
    : left === undefined || right === undefined
      ? "unknown"
      : "changed";

/**
 * Declarations compare within one kind. A declaration that only one side
 * records, including one whose other side records another kind, is unknown.
 */
const compareFormatDeclarations = (
  left: FormatMetadataDeclaration | undefined,
  right: FormatMetadataDeclaration | undefined,
): OccurrenceMetadata["formatDeclaration"] => {
  if (left === undefined && right === undefined) return "absent";
  if (left === undefined || right === undefined || left.kind !== right.kind)
    return "unknown";
  return canonicalJson(left.facts) === canonicalJson(right.facts)
    ? "unchanged"
    : "changed";
};

/** Interpret each pair's declarations once, preserving historical omission. */
const occurrenceMetadata = (input: OccurrencePair): OccurrenceMetadata => {
  const left = input.leftOccurrence;
  const right = input.rightOccurrence;
  return {
    asarPacking: compareAsarPacking(left?.unpacked, right?.unpacked),
    encryption: left?.encrypted === right?.encrypted ? "unchanged" : "changed",
    entryKind: left?.entry_kind === right?.entry_kind ? "unchanged" : "changed",
    formatDeclaration: compareFormatDeclarations(
      formatMetadataDeclaration(left?.format_metadata),
      formatMetadataDeclaration(right?.format_metadata),
    ),
  };
};

/**
 * A node-less metadata record has no content node, so its declared facts are
 * all that comparison checks; an unread payload is not compared. Neither are
 * its limitations: readers derive them from those facts, and their wording
 * can change between REA versions while the record stays the same.
 */
const isDeclarationRecord = (input: ClassifyPathInput): boolean =>
  // Metadata is not inherently a declaration. Only apply this comparison
  // when a producer explicitly recorded a compared one. A record that names
  // content keeps the content comparison.
  input.leftOccurrence?.entry_kind === "metadata" &&
  input.rightOccurrence?.entry_kind === "metadata" &&
  input.leftOccurrence.artifact_id === null &&
  input.rightOccurrence.artifact_id === null &&
  input.metadata.formatDeclaration !== "absent";

/** Facts that both occurrences declare, which need no content. */
const declaredChecks = (input: ClassifyPathInput): DimensionCheck[] => [
  [
    "executable",
    input.leftOccurrence?.executable !== input.rightOccurrence?.executable,
  ],
  ["metadata", declarationChanged(input.metadata)],
];

/**
 * Facts that need both content nodes. Without content, an occurrence's kind
 * and format are guessed from its path, so comparison reads them only when
 * both sides have content.
 */
const nodeChecks = (
  input: ClassifyPathInput,
  left: ArtifactNode,
  right: ArtifactNode,
): DimensionCheck[] => [
  ["content", left.sha256 !== right.sha256],
  [
    "kind",
    input.leftOccurrence?.artifact_kind !==
      input.rightOccurrence?.artifact_kind,
  ],
  [
    "format",
    left.format !== right.format ||
      input.leftOccurrence?.artifact_format !==
        input.rightOccurrence?.artifact_format,
  ],
  ["size", left.size !== right.size],
  [
    "relations",
    JSON.stringify(input.leftRelations) !==
      JSON.stringify(input.rightRelations),
  ],
  [
    "metadata",
    left.media_type !== right.media_type ||
      left.architecture !== right.architecture ||
      left.content_state !== right.content_state ||
      JSON.stringify(left.limitations) !== JSON.stringify(right.limitations) ||
      JSON.stringify(input.leftOccurrence?.limitations) !==
        JSON.stringify(input.rightOccurrence?.limitations),
  ],
];

const nodeFor = (
  occurrence: ArtifactOccurrence | undefined,
  nodes: ReadonlyMap<string, ArtifactNode>,
): ArtifactNode | undefined =>
  occurrence?.artifact_id === null || occurrence?.artifact_id === undefined
    ? undefined
    : nodes.get(occurrence.artifact_id);

const relationsByPath = (
  inventory: InventorySet,
): ReadonlyMap<string, readonly RelationProjection[]> => {
  const output = new Map<string, RelationProjection[]>();
  const occurrences = new Map(
    inventory.occurrences.map((item) => [item.occurrence_id, item]),
  );
  for (const edge of inventory.edges) {
    const occurrence = occurrences.get(edge.occurrence_id);
    // An incomplete inventory can omit the occurrence that names the child.
    if (occurrence?.artifact_id === null || occurrence === undefined) continue;
    const path = occurrence.logical_path;
    const values = output.get(path);
    const projection: RelationProjection = {
      parent_logical_path:
        occurrence.parent_occurrence_id === null
          ? null
          : (occurrences.get(occurrence.parent_occurrence_id)?.logical_path ??
            null),
      // Containment roots are path-normalized to avoid graph-wide deltas, but
      // a source map's target is a semantic content identity, not its parent
      // directory. Preserve that identity in the relation comparison.
      mapped_artifact_id:
        edge.relation === "maps-source" ? edge.parent_artifact_id : null,
      child_artifact_id: occurrence.artifact_id,
      relation: edge.relation,
      logical_path: occurrence.logical_path,
      producer: edge.producer,
    };
    if (values === undefined) output.set(path, [projection]);
    else values.push(projection);
  }
  for (const values of output.values())
    values.sort((left, right) =>
      compareUnicodeCodePoints(canonicalJson(left), canonicalJson(right)),
    );
  return output;
};

interface RelationProjection {
  /** Logical parent is stable across graph-root ID changes. */
  readonly parent_logical_path: string | null;
  /** Content identity is material for a maps-source edge. */
  readonly mapped_artifact_id: string | null;
  readonly child_artifact_id: string;
  readonly relation: ArtifactInventoryResult["edges"][number]["relation"];
  readonly logical_path: string | null;
  /** Producer is semantic provenance; edge ordinal is presentation order. */
  readonly producer: ArtifactInventoryResult["edges"][number]["producer"];
}

const summarize = (
  left: InventorySet,
  right: InventorySet,
  changes: readonly ArtifactChange[],
  covered: boolean,
) => {
  const counts = {
    added: 0,
    removed: 0,
    changed: 0,
    unknown: 0,
    contradiction: 0,
  };
  for (const change of changes) counts[change.classification] += 1;
  // Change rows are keyed by logical path, and one unknown row for a duplicate
  // path stands for every left occurrence on it. Only occurrences on paths
  // without a left-side change are affirmatively unchanged.
  const changedPaths = new Set(
    changes
      .filter(({ classification }) => classification !== "added")
      .map(({ logical_path: path }) => path),
  );
  return {
    unchanged: covered
      ? left.occurrences.filter(
          ({ logical_path: path }) => !changedPaths.has(path),
        ).length
      : 0,
    ...counts,
    unknown: covered
      ? counts.unknown
      : Math.max(
          counts.unknown,
          Math.max(
            left.manifest.occurrence_count,
            right.manifest.occurrence_count,
          ) -
            counts.added -
            counts.removed -
            counts.changed -
            counts.contradiction,
        ),
  };
};

// Differing manifest root digests prove a root content change even when node
// details are unavailable. Fold that fact into an existing root row so one
// logical path keeps one classification.
const applyRootHashChange = (
  left: InventorySet,
  right: InventorySet,
  changes: ArtifactChange[],
  evidenceLinks: readonly string[],
): void => {
  if (left.manifest.root_sha256 === right.manifest.root_sha256) return;
  const index = changes.findIndex((change) => change.logical_path === ".");
  const existing = changes[index];
  if (existing !== undefined) {
    if (
      existing.dimensions.includes("content") ||
      (existing.classification !== "unknown" &&
        existing.classification !== "changed")
    )
      return;
    changes[index] = {
      ...existing,
      classification: "changed",
      dimensions: comparisonDimensionSchema.options.filter(
        (dimension) =>
          dimension === "content" || existing.dimensions.includes(dimension),
      ),
      evidence_links: [
        ...new Set([...existing.evidence_links, ...evidenceLinks]),
      ],
    };
    return;
  }
  const leftRoot = left.occurrences.find(
    (occurrence) => occurrence.logical_path === ".",
  );
  const rightRoot = right.occurrences.find(
    (occurrence) => occurrence.logical_path === ".",
  );
  changes.push({
    classification: "changed",
    logical_path: ".",
    dimensions: ["content"],
    left_occurrence_id: leftRoot?.occurrence_id ?? null,
    right_occurrence_id: rightRoot?.occurrence_id ?? null,
    left_artifact_id: leftRoot?.artifact_id ?? null,
    right_artifact_id: rightRoot?.artifact_id ?? null,
    evidence_links: [...evidenceLinks],
  });
};
