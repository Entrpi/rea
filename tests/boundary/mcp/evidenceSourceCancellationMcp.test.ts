import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, onTestFinished, vi } from "vitest";

import { FUNCTION_COMPARISON_EXAMPLE } from "../../../src/contracts/functionComparisonExample.js";
import { wasmInterfaceComparisonSchema } from "../../../src/contracts/wasm/wasmComparisonContracts.js";
import { AnalysisCancelledError } from "../../../src/domain/analysisErrorCore.js";
import {
  createEvidence,
  parseEvidence,
  type Evidence,
} from "../../../src/domain/evidence.js";
import { createServer } from "../../../src/server/createServer.js";
import { ToolResultDelivery } from "../../../src/server/ToolResultDelivery.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { wasmArtifactFixture } from "../../fixtures/wasm/artifact.js";
import { holdFirstFileRead } from "../../support/holdFirstFileRead.js";

/** A fresh in-process server whose session ledger starts empty. */
const connect = async () => {
  const session = createTestBinarySession(() => {
    throw new Error("Evidence sources must not start a binary provider");
  });
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "evidence-source-cancel", version: "1" });
  onTestFinished(async () => {
    vi.restoreAllMocks();
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, session };
};

const writeSources = async (
  prefix: string,
  left: Evidence,
  right: Evidence,
) => {
  const root = await createTestTempDirectory(prefix);
  const leftPath = join(root, "left.json");
  const rightPath = join(root, "right.json");
  await writeFile(leftPath, JSON.stringify(left));
  await writeFile(rightPath, JSON.stringify(right));
  return {
    leftPath,
    left: { kind: "evidence-file", path: leftPath },
    right: { kind: "evidence-file", path: rightPath },
  };
};

const wasmInspection = (parameter: "i32" | "i64"): Evidence => {
  const report = wasmArtifactFixture();
  report.interface = {
    state: "complete",
    issues: [],
    entries: [
      {
        direction: "export",
        module: null,
        name: "run",
        kind: "func",
        index: 0,
        signature: { kind: "func", params: [parameter], results: [] },
        wat_form: '(export "run" (func 0))',
        issue: null,
      },
    ],
  };
  return createEvidence(
    {
      path: report.artifact.path,
      sha256: report.artifact.sha256,
      format: "file",
    },
    { id: "typed-fixture", name: "Typed fixture", version: "1" },
    {
      operation: "inspect_wasm_artifact",
      parameters: { path: report.artifact.path },
      result: report,
      confidence: "observed",
    },
  );
};

it("retains the file-loaded inspections that a cancelled WASM comparison cites", async () => {
  const { client, session } = await connect();
  const left = wasmInspection("i32");
  const right = wasmInspection("i64");
  const sources = await writeSources("rea-wasm-partial-sources-", left, right);
  const controller = new AbortController();
  // Cancel the request while the complete report is built; the comparison
  // is then delivered as a cancelled partial and retained by the session.
  vi.spyOn(wasmInterfaceComparisonSchema, "parse").mockImplementationOnce(
    (report) => {
      controller.abort(new Error("cancel at the final handoff"));
      return wasmInterfaceComparisonSchema.parse(report);
    },
  );
  const partialDelivery = vi.spyOn(
    ToolResultDelivery.prototype,
    "toPartialErrorToolResult",
  );
  const call = client
    .callTool(
      {
        name: "compare_wasm_interfaces",
        arguments: { left: sources.left, right: sources.right, scope: "both" },
      },
      { signal: controller.signal },
    )
    .then(
      () => "completed",
      (error: unknown) => error,
    );
  expect(await call).toMatchObject({
    message: expect.stringContaining("cancel at the final handoff"),
  });
  await vi.waitFor(() => expect(partialDelivery).toHaveBeenCalledOnce());
  const [error] = partialDelivery.mock.calls[0]!;
  expect(error).toBeInstanceOf(AnalysisCancelledError);
  const partial = parseEvidence(error.partialObservation);
  expect(partial).toMatchObject({
    operation: "compare_wasm_interfaces",
    evidence_links: [left.evidence_id, right.evidence_id],
  });
  // The session holds the partial and both inspections it cites.
  for (const id of [left.evidence_id, right.evidence_id, partial.evidence_id])
    expect(session.evidenceForAnalysis(id)?.evidence_id).toBe(id);
});

it("leaves the session unchanged when a comparison is cancelled during an Evidence-file read", async () => {
  const { client, session } = await connect();
  const sources = await writeSources(
    "rea-function-source-cancel-",
    FUNCTION_COMPARISON_EXAMPLE.left,
    FUNCTION_COMPARISON_EXAMPLE.right,
  );
  const before = session.exportEvidenceBundle();
  const reader = await holdFirstFileRead(sources.leftPath);
  const controller = new AbortController();
  onTestFinished(() => {
    controller.abort();
    reader.release();
  });
  const settled = vi.spyOn(ToolResultDelivery.prototype, "toCallToolResult");
  const call = client
    .callTool(
      {
        name: "compare_functions",
        arguments: { left: sources.left, right: sources.right },
      },
      { signal: controller.signal },
    )
    .then(
      () => "completed",
      (error: unknown) => error,
    );
  await reader.firstRead;
  controller.abort(new Error("cancel during the Evidence-file read"));
  reader.release();
  expect(await call).toMatchObject({
    message: expect.stringContaining("cancel during the Evidence-file read"),
  });
  await vi.waitFor(() => expect(settled).toHaveBeenCalled());
  expect(settled.mock.calls[0]![0]).toMatchObject({
    ok: false,
    error: expect.any(AnalysisCancelledError),
  });
  expect(session.exportEvidenceBundle()).toEqual(before);

  // The same request completes once it is not cancelled.
  await client.ping();
  const retry = await client.callTool({
    name: "compare_functions",
    arguments: { left: sources.left, right: sources.right },
  });
  expect(retry.isError, JSON.stringify(retry)).not.toBe(true);
  expect(parseEvidence(retry.structuredContent).evidence_links).toEqual([
    FUNCTION_COMPARISON_EXAMPLE.left.evidence_id,
    FUNCTION_COMPARISON_EXAMPLE.right.evidence_id,
  ]);
});
