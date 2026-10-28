import { expect, it, vi } from "vitest";
import { createEvidence, parseEvidence } from "../../domain/evidence.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { wasmInterfaceComparisonSchema } from "../../contracts/wasm/wasmComparisonContracts.js";
import { compareWasmInterfaces } from "./WasmInterfaceComparisonService.js";
import { wasmArtifactSchema } from "../../domain/wasm/wasmArtifact.js";
import * as wasmInterfaceModule from "../../domain/wasm/wasmInterface.js";
import {
  WASM_INTERFACE_REPRESENTATION_BYTES,
  wasmInterfaceEntryRepresentationBytes,
  type WasmInterface,
} from "../../domain/wasm/wasmInterface.js";
import { wasmArtifactFixture } from "../../../tests/fixtures/wasm/artifact.js";

const facts = (
  name: string,
  parameter: "i32" | "i64" = "i32",
): WasmInterface => ({
  state: "complete",
  issues: [],
  entries: [
    {
      direction: "export",
      module: null,
      name,
      kind: "func",
      index: 0,
      signature: { kind: "func", params: [parameter], results: [] },
      wat_form: `(export "${name}" (func 0))`,
      issue: null,
    },
  ],
});
const evidence = (
  interfaceFacts?: WasmInterface,
  format: "file" | "pe" = "file",
) => {
  const report = wasmArtifactFixture();
  if (interfaceFacts !== undefined) report.interface = interfaceFacts;
  return createEvidence(
    {
      path: report.artifact.path,
      sha256: report.artifact.sha256,
      format,
    },
    { id: "fixture", name: "typed fixture", version: "1" },
    {
      operation: "inspect_wasm_artifact",
      parameters: { path: report.artifact.path },
      result: report,
      confidence: "observed",
    },
  );
};
const compare = async (
  left: ReturnType<typeof evidence>,
  right: ReturnType<typeof evidence>,
) => {
  const result = await compareWasmInterfaces({ left, right, scope: "both" });
  if (!result.ok) throw result.error;
  return wasmInterfaceComparisonSchema.parse(result.value.normalized_result);
};

it("reports all five comparison states, including duplicate ambiguity and explicit selected scope", async () => {
  const left = facts("changed");
  const right = facts("changed", "i64");
  left.entries.push(
    ...facts("unchanged").entries,
    ...facts("removed").entries,
    ...facts("dup").entries,
    ...facts("dup").entries,
  );
  right.entries.push(
    ...facts("unchanged").entries,
    ...facts("added").entries,
    ...facts("dup").entries,
  );
  const report = await compare(evidence(left), evidence(right));
  expect(report.summary).toEqual({
    changed: 1,
    unchanged: 1,
    removed: 1,
    added: 1,
    unknown: 1,
  });
  expect(report.changes.find((c) => c.name === "dup")).toMatchObject({
    state: "unknown",
    left: [expect.anything(), expect.anything()],
    right: [expect.anything()],
  });
  const selected = await compareWasmInterfaces({
    left: evidence(left),
    right: evidence(right),
    scope: "imports",
  });
  if (!selected.ok) throw selected.error;
  expect(selected.value.normalized_result).toMatchObject({
    changes: [],
    coverage: "complete-within-inputs",
  });
});

it("withholds absence claims for historical or partial inventories and unsupported signatures", async () => {
  const known = facts("f");
  const absent = await compare(evidence(), evidence(known));
  expect(absent).toMatchObject({
    coverage: "partial",
    changes: [{ state: "unknown" }],
  });
  const partial: WasmInterface = {
    state: "partial",
    issues: ["unread import table"],
    entries: [],
  };
  expect(await compare(evidence(partial), evidence(known))).toMatchObject({
    changes: [{ state: "unknown" }],
  });
  const unsupported = facts("f");
  unsupported.entries[0]!.signature = null;
  expect(await compare(evidence(known), evidence(unsupported))).toMatchObject({
    changes: [{ state: "unknown" }],
  });
  const partialMatch = facts("f");
  partialMatch.state = "partial";
  partialMatch.issues = ["Later imports were not examined"];
  expect(await compare(evidence(partialMatch), evidence(known))).toMatchObject({
    changes: [{ state: "unknown" }],
  });
  expect(await compare(evidence(), evidence())).toMatchObject({
    coverage: "unknown",
    changes: [],
  });
});

it("authenticates semantic Evidence and rejects altered artifact digests", async () => {
  const left = JSON.parse(JSON.stringify(evidence(facts("f"))));
  left.normalized_result.interface.entries[0].name = "tampered";
  expect(
    await compareWasmInterfaces({
      left,
      right: evidence(facts("f")),
      scope: "both",
    }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
  const rebound = JSON.parse(JSON.stringify(evidence(facts("f"))));
  rebound.subject.digest.sha256 = "b".repeat(64);
  expect(
    await compareWasmInterfaces({
      left: rebound,
      right: evidence(facts("f")),
      scope: "both",
    }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
});

it("requires the producer's file subject format even for authentic Evidence", async () => {
  const wrongFormat = evidence(facts("f"), "pe");
  expect(parseEvidence(wrongFormat)).toEqual(wrongFormat);
  expect(
    await compareWasmInterfaces({
      left: wrongFormat,
      right: evidence(facts("f")),
      scope: "both",
    }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
});

it("resolves exact retained references", async () => {
  const left = evidence(facts("f"));
  const right = evidence(facts("f", "i64"));
  const references = {
    left: { kind: "retained-evidence", evidence_id: left.evidence_id },
    right: { kind: "retained-evidence", evidence_id: right.evidence_id },
    scope: "both",
  };
  expect(await compareWasmInterfaces(references)).toMatchObject({
    ok: false,
    error: { _tag: "EvidenceIntegrityError" },
  });
  const result = await compareWasmInterfaces(references, {}, (id) =>
    id === left.evidence_id ? left : right,
  );
  if (!result.ok) throw result.error;
  expect(result.value.evidence_links).toEqual([
    left.evidence_id,
    right.evidence_id,
  ]);
});

/** 2001 exports per side: both loops pass several batch checkpoints. */
const largeInterface = (): WasmInterface => {
  const large = facts("f");
  large.entries.push(
    ...Array.from({ length: 2000 }, (_, i) => facts(`f${i}`).entries[0]!),
  );
  return large;
};

/** Queue the abort once a hook has seen `after` entries; only a later checkpoint can dispatch it. */
const abortAfter = (
  after: number,
  controller: AbortController,
  reason: unknown,
) => {
  let seen = 0;
  return {
    entry: () => {
      if (++seen === after) setImmediate(() => controller.abort(reason));
    },
    seen: () => seen,
  };
};

it("observes cancellation at a batch checkpoint while grouping entries", async () => {
  const controller = new AbortController();
  const reason = { request: "cancel between grouping batches" };
  const hook = abortAfter(300, controller, reason);
  const parseArtifact = wasmArtifactSchema.safeParse.bind(wasmArtifactSchema);
  // Count each entry the grouping loop reads; no export matches "imports", so
  // the classification loop has no groups and no checkpoints of its own.
  const parse = vi
    .spyOn(wasmArtifactSchema, "safeParse")
    .mockImplementation((value) => {
      const parsed = parseArtifact(value);
      const entries = parsed.data?.interface?.entries;
      if (entries === undefined) return parsed;
      parsed.data!.interface!.entries = new Proxy(entries, {
        get: (target, key, receiver) => {
          if (typeof key === "string" && /^\d+$/u.test(key)) hook.entry();
          return Reflect.get(target, key, receiver) as unknown;
        },
      });
      return parsed;
    });
  try {
    const cancelled = await compareWasmInterfaces(
      {
        left: evidence(largeInterface()),
        right: evidence(largeInterface()),
        scope: "imports",
      },
      { signal: controller.signal },
    );
    if (cancelled.ok) throw new Error("Expected cancellation between batches");
    expect(cancelled.error).toMatchObject({ _tag: "AnalysisCancelledError" });
    expect(cancelled.error.cause).toBe(reason);
    expect(cancelled.error.partialObservation).toBeUndefined();
    // The first batch completed and the loop stopped before its last entry.
    expect(hook.seen()).toBeGreaterThanOrEqual(300);
    expect(hook.seen()).toBeLessThan(4002);
  } finally {
    parse.mockRestore();
  }
});

it("observes cancellation at a batch checkpoint while classifying groups", async () => {
  const controller = new AbortController();
  const reason = { request: "cancel between classification batches" };
  const hook = abortAfter(300, controller, reason);
  const representationBytes =
    wasmInterfaceModule.wasmInterfaceEntryRepresentationBytes;
  // Each group charges its left and right entry before its checkpoint.
  const charge = vi
    .spyOn(wasmInterfaceModule, "wasmInterfaceEntryRepresentationBytes")
    .mockImplementation((entry) => {
      hook.entry();
      return representationBytes(entry);
    });
  try {
    const cancelled = await compareWasmInterfaces(
      {
        left: evidence(largeInterface()),
        right: evidence(largeInterface()),
        scope: "both",
      },
      { signal: controller.signal },
    );
    if (cancelled.ok) throw new Error("Expected cancellation between batches");
    expect(cancelled.error).toMatchObject({ _tag: "AnalysisCancelledError" });
    expect(cancelled.error.cause).toBe(reason);
    expect(cancelled.error.partialObservation).toBeUndefined();
    expect(hook.seen()).toBeGreaterThanOrEqual(300);
    expect(hook.seen()).toBeLessThan(4002);
  } finally {
    charge.mockRestore();
  }
});

/** One inventory under the comparison cap; two of them exceed it together. */
const admittedInventory = (label: string): WasmInterface => {
  const base = facts(label).entries[0]!;
  const minimum = Math.floor(WASM_INTERFACE_REPRESENTATION_BYTES / 2) + 4096;
  let low = 0;
  let high = 4_000_000;
  let best = 0;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const name = `${label}-${"n".repeat(mid)}`;
    const bytes = wasmInterfaceEntryRepresentationBytes({
      ...base,
      name,
      wat_form: `(export "${name}" (func 0))`,
    });
    if (bytes >= minimum) {
      best = mid;
      high = mid - 1;
    } else low = mid + 1;
  }
  const name = `${label}-${"n".repeat(best)}`;
  const entry = {
    ...base,
    name,
    wat_form: `(export "${name}" (func 0))`,
  };
  const bytes = wasmInterfaceEntryRepresentationBytes(entry);
  if (
    bytes >= WASM_INTERFACE_REPRESENTATION_BYTES ||
    bytes + 512 >= WASM_INTERFACE_REPRESENTATION_BYTES
  )
    throw new Error("Sized inventory is not individually admitted");
  return { state: "complete", issues: [], entries: [entry] };
};

it("refuses two admitted inventories that together exceed the comparison cap", async () => {
  const left = admittedInventory("left");
  const right = admittedInventory("right");
  const empty: WasmInterface = { state: "complete", issues: [], entries: [] };
  const alone = await compareWasmInterfaces({
    left: evidence(left),
    right: evidence(empty),
    scope: "both",
  });
  expect(alone.ok).toBe(true);
  const combined = await compareWasmInterfaces({
    left: evidence(left),
    right: evidence(right),
    scope: "both",
  });
  expect(combined.ok).toBe(false);
  if (combined.ok) throw new Error("Expected comparison allowance refusal");
  const projected = projectAnalysisError(combined.error);
  expect(projected.retryable).toBe(false);
  expect(projected.code).toBe("resource_constraint");
  expect(combined.error).toMatchObject({ resource: "capacity" });
  expect(projected.remediation.action).toContain(
    "The WASM interface comparison inventory",
  );
  expect(projected.remediation.action).toContain("fixed byte allowance");
  expect(projected.remediation.action).not.toContain("fixed count");
  expect(projected.remediation.action).not.toMatch(
    /Wait for an active analysis/u,
  );
});

it.each([false, true])(
  "keeps a one-sided unsupported interface unknown with reverse=%s",
  async (reverse) => {
    const empty: WasmInterface = { state: "complete", issues: [], entries: [] };
    const unsupported = facts("exception");
    unsupported.entries[0]!.signature = null;
    unsupported.entries[0]!.issue = "Unsupported exnref global type";
    const sides = reverse ? [unsupported, empty] : [empty, unsupported];
    expect(await compare(evidence(sides[0]), evidence(sides[1]))).toMatchObject(
      {
        coverage: "partial",
        summary: { added: 0, removed: 0, unknown: 1 },
        changes: [{ state: "unknown" }],
      },
    );
  },
);

it("preserves the caller reason when comparison admission is already cancelled", async () => {
  const left = evidence(facts("f"));
  const right = evidence(facts("f"));
  const reason = { request: "cancel before comparison" };
  const preAborted = await compareWasmInterfaces(
    { left, right, scope: "both" },
    { signal: AbortSignal.abort(reason) },
  );
  if (preAborted.ok) throw new Error("Expected cancellation before comparison");
  expect(preAborted.error.cause).toBe(reason);
});

it("retains the complete comparison when cancelled at the final handoff", async () => {
  const left = evidence(facts("changed"));
  const right = evidence(facts("changed", "i64"));
  const reason = { request: "cancel completed comparison" };
  const controller = new AbortController();
  // Queue the abort while the complete report is built, after the last batch
  // checkpoint: only the service's own final yield can dispatch it. The
  // one-time implementation is consumed first, so the nested parse is the real one.
  const parse = vi
    .spyOn(wasmInterfaceComparisonSchema, "parse")
    .mockImplementationOnce((report) => {
      setImmediate(() => controller.abort(reason));
      return wasmInterfaceComparisonSchema.parse(report);
    });
  try {
    const result = await compareWasmInterfaces(
      { left, right, scope: "both" },
      { signal: controller.signal },
    );
    if (result.ok)
      throw new Error("Expected cancellation during final handoff");
    expect(result.error).toMatchObject({ _tag: "AnalysisCancelledError" });
    expect(result.error.cause).toBe(reason);
    const partial = parseEvidence(result.error.partialObservation);
    expect(partial).toMatchObject({
      operation: "compare_wasm_interfaces",
      confidence: "derived",
      authority: "analyst-inference",
      evidence_links: [left.evidence_id, right.evidence_id],
    });
    expect(
      wasmInterfaceComparisonSchema.parse(partial.normalized_result),
    ).toMatchObject({
      coverage: "complete-within-inputs",
      summary: { changed: 1, added: 0, removed: 0, unchanged: 0, unknown: 0 },
    });
  } finally {
    parse.mockRestore();
  }
});

it("does not report unexpected output-construction failures as invalid caller Evidence", async () => {
  const failure = new Error("comparison output construction failed");
  const parse = vi
    .spyOn(wasmInterfaceComparisonSchema, "parse")
    .mockImplementation(() => {
      throw failure;
    });
  try {
    await expect(
      compareWasmInterfaces({
        left: evidence(facts("f")),
        right: evidence(facts("f")),
        scope: "both",
      }),
    ).rejects.toBe(failure);
  } finally {
    parse.mockRestore();
  }
});
