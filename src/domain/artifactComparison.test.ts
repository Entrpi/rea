import { expect, it } from "vitest";
import { ARTIFACT_COMPARISON_EXAMPLE } from "../contracts/artifactComparisonExample.js";
import { compareArtifacts } from "./artifactComparison.js";
import {
  artifactInventoryResultSchema,
  type ArtifactOccurrence,
} from "./artifactGraph.js";
import { artifactGraphDigest, artifactManifestId } from "./artifactIdentity.js";
import { createEvidence } from "./evidence.js";

/** Recommit observation variants so comparisons exercise valid Evidence carriers. */
const observation = (
  facts: Pick<ArtifactOccurrence, "hash_status"> &
    Partial<Pick<ArtifactOccurrence, "unpacked" | "format_metadata">>,
  changedContent = false,
) => {
  const source = changedContent
    ? ARTIFACT_COMPARISON_EXAMPLE.right
    : ARTIFACT_COMPARISON_EXAMPLE.left;
  const inventory = artifactInventoryResultSchema.parse(
    source.normalized_result,
  );
  inventory.occurrences = inventory.occurrences.map((occurrence) => ({
    ...occurrence,
    ...facts,
  }));
  const graphSha256 = artifactGraphDigest({
    nodes: inventory.nodes,
    occurrences: inventory.occurrences,
    edges: inventory.edges,
    contradictions: inventory.integrity_contradictions,
  });
  inventory.manifest.graph_sha256 = graphSha256;
  inventory.manifest.manifest_id = artifactManifestId(
    inventory.manifest.root_artifact_id,
    graphSha256,
  );
  return createEvidence(
    {
      path: "packing-observation",
      sha256: inventory.manifest.root_sha256,
      format: inventory.manifest.root_format,
    },
    source.provider,
    {
      operation: "inventory_artifact",
      parameters: {},
      result: inventory,
      confidence: "observed",
      authority: "shipped-artifact",
    },
  );
};

const packingObservation = (
  unpacked: boolean | undefined,
  hashStatus: ArtifactOccurrence["hash_status"] = "verified",
  changedContent = false,
) =>
  observation(
    {
      ...(unpacked === undefined ? {} : { unpacked }),
      hash_status: hashStatus,
    },
    changedContent,
  );

it.each([true, false, undefined])(
  "retains equality for matching packing observations %s",
  (unpacked) => {
    const evidence = packingObservation(unpacked);
    expect(compareArtifacts(evidence, evidence)).toMatchObject({
      status: "unchanged",
      changes: [],
    });
  },
);

it.each([
  [false, true],
  [true, false],
] as const)("compares known packing declarations %s to %s", (left, right) => {
  expect(
    compareArtifacts(packingObservation(left), packingObservation(right)),
  ).toMatchObject({
    status: "changed",
    changes: [{ classification: "changed", dimensions: ["metadata"] }],
  });
});

it.each([
  [true, undefined],
  [undefined, true],
  [false, undefined],
  [undefined, false],
] as const)(
  "keeps missing packing metadata unknown: %s to %s",
  (left, right) => {
    const result = compareArtifacts(
      packingObservation(left),
      packingObservation(right),
    );
    expect(result).toMatchObject({
      status: "unknown",
      changes: [{ classification: "unknown", dimensions: ["availability"] }],
    });
    expect(result.limitations).toEqual([
      expect.stringContaining("omitted metadata may be a legacy observation"),
    ]);
  },
);

it("retains proven content changes alongside unknown packing metadata", () => {
  expect(
    compareArtifacts(
      packingObservation(undefined),
      packingObservation(true, "verified", true),
    ),
  ).toMatchObject({
    status: "changed",
    changes: [
      { classification: "changed", dimensions: ["content", "availability"] },
    ],
  });
});

it("retains known packing changes when content is unavailable", () => {
  expect(
    compareArtifacts(
      packingObservation(false),
      packingObservation(true, "unavailable"),
    ),
  ).toMatchObject({
    status: "changed",
    changes: [
      { classification: "changed", dimensions: ["metadata", "availability"] },
    ],
  });
});

it("keeps unavailable content unknown when packing declarations agree", () => {
  expect(
    compareArtifacts(
      packingObservation(true),
      packingObservation(true, "unavailable"),
    ),
  ).toMatchObject({
    status: "unknown",
    changes: [{ classification: "unknown", dimensions: ["availability"] }],
  });
});

it("keeps integrity contradictions ahead of packing differences", () => {
  expect(
    compareArtifacts(
      packingObservation(false),
      packingObservation(true, "mismatched"),
    ),
  ).toMatchObject({
    status: "contradiction",
    changes: [{ classification: "contradiction", dimensions: ["integrity"] }],
  });
});

type FormatMetadata = NonNullable<ArtifactOccurrence["format_metadata"]>;

const declared = (formatMetadata: FormatMetadata) =>
  observation({ hash_status: "verified", format_metadata: formatMetadata });

const pyInstallerEntry: FormatMetadata = {
  kind: "pyinstaller-entry",
  container: "carchive",
  container_name: null,
  index: 0,
  source_name: "helper",
  type_code: "m",
  relative_offset: 0,
  directory_record_offset: null,
  directory_record_size: null,
  compression_flag: 0,
  bytecode_header: "not-bytecode",
  bytecode_magic: null,
  pyz_status: "not-pyz",
  pyz_sha256: null,
  pyz_python_magic: null,
  pyz_python_version: null,
  pyz_entry_count: null,
  encryption_source: null,
};
const nodeSeaEntry: FormatMetadata = {
  kind: "node-sea-entry",
  role: "asset",
  source_path: "data/asset.txt",
  index: 0,
};
const espImageSegment: FormatMetadata = {
  kind: "esp-image-segment",
  index: 1,
  load_addr: 0x3fc8_8000,
  data_len: 4,
  header_offset: 24,
  classification: "loaded",
};

// Each compared kind: a base, a declared change and a layout-only change.
const declarations = [
  [
    "pyinstaller-entry",
    pyInstallerEntry,
    { ...pyInstallerEntry, type_code: "s" },
    { ...pyInstallerEntry, index: 5, relative_offset: 64 },
  ],
  [
    "node-sea-entry",
    nodeSeaEntry,
    { ...nodeSeaEntry, role: "code-cache" },
    { ...nodeSeaEntry, index: 3 },
  ],
  [
    "esp-image-segment",
    espImageSegment,
    { ...espImageSegment, load_addr: 0x3fc8_a000 },
    { ...espImageSegment, header_offset: 64, classification: "unknown" },
  ],
] as const satisfies readonly (readonly [
  string,
  FormatMetadata,
  FormatMetadata,
  FormatMetadata,
])[];

it.each(declarations)(
  "compares %s declarations without their layout",
  (_kind, base, change, layout) => {
    expect(compareArtifacts(declared(base), declared(layout))).toMatchObject({
      status: "unchanged",
      changes: [],
    });
    expect(compareArtifacts(declared(base), declared(change))).toMatchObject({
      status: "changed",
      changes: [{ classification: "changed", dimensions: ["metadata"] }],
    });
  },
);

it.each(declarations)(
  "retains a changed %s declaration when content is unavailable",
  (_kind, base, change) => {
    expect(
      compareArtifacts(
        declared(base),
        observation({ hash_status: "unavailable", format_metadata: change }),
      ),
    ).toMatchObject({
      status: "changed",
      changes: [
        { classification: "changed", dimensions: ["metadata", "availability"] },
      ],
    });
  },
);

it.each(declarations)(
  "keeps one-sided %s declarations unknown",
  (_kind, base) => {
    const omitted = observation({ hash_status: "verified" });
    for (const [left, right] of [
      [declared(base), omitted],
      [omitted, declared(base)],
    ] as const) {
      const result = compareArtifacts(left, right);
      expect(result).toMatchObject({
        status: "unknown",
        changes: [{ classification: "unknown", dimensions: ["availability"] }],
      });
      expect(result.limitations).toEqual([
        expect.stringContaining(
          "Format metadata declarations are recorded on only one side",
        ),
      ]);
    }
  },
);

it("keeps declarations of different kinds unknown", () => {
  expect(
    compareArtifacts(declared(pyInstallerEntry), declared(nodeSeaEntry)),
  ).toMatchObject({
    status: "unknown",
    changes: [{ classification: "unknown", dimensions: ["availability"] }],
  });
});

it.each([
  [
    "godot-pck-entry",
    {
      kind: "godot-pck-entry",
      index: 0,
      source_path: "res://scenes/main.gd",
      declared_offset: 0,
      flags: 0,
      md5_status: "declared",
    },
    {
      kind: "godot-pck-entry",
      index: 3,
      source_path: "scenes/main.gd",
      declared_offset: 96,
      flags: 0,
      md5_status: "declared",
    },
  ],
  [
    "esp-image-signature-block",
    {
      kind: "esp-image-signature-block",
      index: 0,
      version: 2,
      scheme: "rsa",
      sha_version: null,
      curve_id: null,
      digest_algorithm: "sha256",
      image_digest: "a".repeat(64),
      image_digest_matches: true,
      public_key_sha256: "b".repeat(64),
      signature_status: "unverified",
    },
    {
      kind: "esp-image-signature-block",
      index: 0,
      version: 2,
      scheme: "rsa",
      sha_version: null,
      curve_id: null,
      digest_algorithm: "sha256",
      image_digest: "a".repeat(64),
      image_digest_matches: false,
      public_key_sha256: "b".repeat(64),
      signature_status: "unverified",
    },
  ],
] as const satisfies readonly (readonly [
  string,
  FormatMetadata,
  FormatMetadata,
])[])("does not compare %s metadata", (_kind, left, right) => {
  for (const other of [
    declared(right),
    observation({ hash_status: "verified" }),
  ])
    expect(compareArtifacts(declared(left), other)).toMatchObject({
      status: "unchanged",
      changes: [],
      limitations: [],
    });
});
