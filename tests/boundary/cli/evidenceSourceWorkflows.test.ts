import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { FUNCTION_COMPARISON_EXAMPLE } from "../../../src/contracts/functionComparisonExample.js";
import { INVESTIGATION_EXAMPLES } from "../../../src/contracts/investigationExamples.js";
import {
  JAVASCRIPT_APPLICATION_VERSION_COMPARISON_EXAMPLE,
  JAVASCRIPT_FEATURE_TRACE_EXAMPLE,
  SOURCE_TO_BUNDLE_COMPARISON_EXAMPLE,
} from "../../../src/contracts/javascript/javascriptApplicationWorkflowExamples.js";
import { JAVASCRIPT_EXPORT_SHAPE_COMPARISON_EXAMPLE } from "../../../src/contracts/javascript/javascriptExportShapeComparisonExample.js";
import { MANAGED_MEMBER_COMPARISON_EXAMPLE } from "../../../src/contracts/managed/managedWorkflowExamples.js";
import {
  createEvidence,
  parseEvidence,
  type Evidence,
} from "../../../src/domain/evidence.js";
import { createEvidenceBundle } from "../../../src/domain/evidenceBundle.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { wasmArtifactFixture } from "../../fixtures/wasm/artifact.js";
import {
  cliTest,
  runFileCli,
  type SharedMcpCall,
  type TestCli,
} from "../../support/cli/cliFixture.js";

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

const wasmLeft = wasmInspection("i32");

/**
 * Each tool naming Evidence through the shared source contract, with its CLI
 * command: one taking the request JSON, or one taking each source as a saved
 * Evidence file argument.
 */
const workflows: readonly {
  readonly tool: string;
  readonly command?: string;
  readonly fileCommand?: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly sources: readonly string[];
}[] = [
  {
    tool: "compare_functions",
    input: FUNCTION_COMPARISON_EXAMPLE,
    sources: ["left", "right"],
  },
  {
    tool: "compare_process_captures",
    fileCommand: "compare-process-captures",
    input: INVESTIGATION_EXAMPLES.compare_process_captures.input,
    sources: ["left", "right"],
  },
  {
    // The CLI command compares two PE files instead of saved Evidence.
    tool: "compare_managed_members",
    input: MANAGED_MEMBER_COMPARISON_EXAMPLE,
    sources: ["left", "right"],
  },
  {
    tool: "compare_wasm_interfaces",
    command: "compare-wasm-interfaces",
    input: { left: wasmLeft, right: wasmInspection("i64"), scope: "both" },
    sources: ["left", "right"],
  },
  {
    tool: "trace_application_feature",
    command: "trace-application-feature",
    input: JAVASCRIPT_FEATURE_TRACE_EXAMPLE,
    sources: ["application"],
  },
  {
    tool: "trace_javascript_semantics",
    command: "trace-javascript-semantics",
    input: {
      application: JAVASCRIPT_FEATURE_TRACE_EXAMPLE.application,
      query: {
        seed: { kind: "literal", value: true },
        direction: "backward-provenance",
      },
    },
    sources: ["application"],
  },
  {
    tool: "compare_application_versions",
    command: "compare-application-versions",
    input: JAVASCRIPT_APPLICATION_VERSION_COMPARISON_EXAMPLE,
    sources: ["left", "right"],
  },
  {
    tool: "compare_source_to_bundle",
    command: "compare-source-to-bundle",
    input: SOURCE_TO_BUNDLE_COMPARISON_EXAMPLE,
    sources: ["application"],
  },
  {
    tool: "compare_javascript_export_shapes",
    command: "compare-javascript-export-shapes",
    input: JAVASCRIPT_EXPORT_SHAPE_COMPARISON_EXAMPLE,
    sources: ["left", "right"],
  },
];

/** Replace each source of a workflow's inline request with another form. */
const withSources = (
  workflow: (typeof workflows)[number],
  form: (record: Evidence, field: string) => unknown,
): Record<string, unknown> => ({
  ...workflow.input,
  ...Object.fromEntries(
    workflow.sources.map((field) => [
      field,
      form(parseEvidence(workflow.input[field]), field),
    ]),
  ),
});

/** Every source record, alone in its own file and together in one bundle. */
const writeSources = async (prefix: string) => {
  const root = await createTestTempDirectory(prefix);
  const records = new Map<string, Evidence>();
  for (const workflow of workflows)
    for (const field of workflow.sources) {
      const record = parseEvidence(workflow.input[field]);
      records.set(record.evidence_id, record);
    }
  for (const [id, record] of records)
    await writeFile(join(root, `${id}.json`), JSON.stringify(record));
  const bundle = join(root, "sources.json");
  await writeFile(
    bundle,
    JSON.stringify(createEvidenceBundle([...records.values()])),
  );
  return { root, bundle };
};

const sharedMcp = async (cli: TestCli): Promise<SharedMcpCall> => {
  const call = await cli.sharedMcpCall?.();
  if (call === undefined) throw new Error("Expected shared MCP session");
  return call;
};

const runCli = async (
  cli: TestCli,
  root: string,
  command: string,
  input: Record<string, unknown>,
) => {
  const request = join(root, "request.json");
  await writeFile(request, JSON.stringify(input));
  return runFileCli(cli, {
    arguments: [command, request, "--json"],
    cwd: root,
  });
};

cliTest(
  "gives one result for inline, retained and Evidence-file sources through MCP and the CLI",
  async ({ cli }) => {
    const { root, bundle } = await writeSources("rea-evidence-sources-");
    const call = await sharedMcp(cli);
    const imported = await call("import_evidence_bundle", { path: bundle });
    expect(imported.isError, JSON.stringify(imported)).not.toBe(true);
    for (const workflow of workflows) {
      const mcp = async (input: Record<string, unknown>) => {
        const reply = await call(workflow.tool, input);
        expect(reply.isError, JSON.stringify(reply)).not.toBe(true);
        return parseEvidence(reply.structuredContent).evidence_id;
      };
      const inline = await mcp(workflow.input);
      for (const [form, input] of [
        [
          "retained",
          withSources(workflow, ({ evidence_id }) => ({
            kind: "retained-evidence",
            evidence_id,
          })),
        ],
        [
          "file",
          withSources(workflow, ({ evidence_id }) => ({
            kind: "evidence-file",
            path: join(root, `${evidence_id}.json`),
          })),
        ],
        [
          "bundle record",
          withSources(workflow, ({ evidence_id }) => ({
            kind: "evidence-file",
            path: bundle,
            evidence_id,
          })),
        ],
      ] as const)
        expect(await mcp(input), `${workflow.tool} ${form}`).toBe(inline);
      // Each side of one request can use a different form.
      if (workflow.sources.length > 1)
        expect(
          await mcp(
            withSources(workflow, ({ evidence_id }, field) =>
              field === "right"
                ? { kind: "retained-evidence", evidence_id }
                : {
                    kind: "evidence-file",
                    path: join(root, `${evidence_id}.json`),
                  },
            ),
          ),
          `${workflow.tool} file and retained`,
        ).toBe(inline);
      if (workflow.fileCommand !== undefined) {
        const files = workflow.sources.map(
          (field) => `${parseEvidence(workflow.input[field]).evidence_id}.json`,
        );
        const result = await runFileCli(cli, {
          arguments: [workflow.fileCommand, ...files, "--json"],
          cwd: root,
        });
        expect(result.exitCode, result.stdout).toBe(0);
        expect(
          parseEvidence(result.json).evidence_id,
          `${workflow.fileCommand} files`,
        ).toBe(inline);
      }
      if (workflow.command === undefined) continue;
      // The CLI resolves relative Evidence-file paths from its working directory.
      for (const [form, input] of [
        ["inline", workflow.input],
        [
          "file",
          withSources(workflow, ({ evidence_id }) => ({
            kind: "evidence-file",
            path: `${evidence_id}.json`,
          })),
        ],
        [
          "bundle record",
          withSources(workflow, ({ evidence_id }) => ({
            kind: "evidence-file",
            path: "sources.json",
            evidence_id,
          })),
        ],
      ] as const) {
        const result = await runCli(cli, root, workflow.command, input);
        expect(result.exitCode, result.stdout).toBe(0);
        expect(
          parseEvidence(result.json).evidence_id,
          `${workflow.command} ${form}`,
        ).toBe(inline);
      }
    }
  },
);

cliTest(
  "refuses an unselected bundle record and a malformed reference at the caller's field path",
  async ({ cli }) => {
    const { root, bundle } = await writeSources("rea-evidence-refusals-");
    const call = await sharedMcp(cli);
    const ambiguous = await call("compare_functions", {
      left: FUNCTION_COMPARISON_EXAMPLE.left,
      right: { kind: "evidence-file", path: bundle },
    });
    expect(parseMcpToolError(ambiguous).error).toMatchObject({
      code: "invalid_request",
      message: expect.stringContaining("right.evidence_id"),
      details: {
        operation: "compare_functions",
        issues: [expect.objectContaining({ path: ["right", "evidence_id"] })],
      },
    });
    // Evidence of another kind, read from a file, is refused at its field.
    const wrongKind = await call("compare_wasm_interfaces", {
      left: {
        kind: "evidence-file",
        path: join(root, `${wasmLeft.evidence_id}.json`),
      },
      right: {
        kind: "evidence-file",
        path: join(
          root,
          `${FUNCTION_COMPARISON_EXAMPLE.right.evidence_id}.json`,
        ),
      },
      scope: "both",
    });
    expect(parseMcpToolError(wrongKind).error).toMatchObject({
      code: "invalid_request",
      details: {
        operation: "compare_wasm_interfaces",
        issues: [expect.objectContaining({ path: ["right"] })],
      },
    });
    // inspect_analysis_view names its own source field through the same reader.
    const view = await call("inspect_analysis_view", {
      source: { kind: "evidence-file", path: bundle },
      view: { kind: "summary" },
    });
    expect(parseMcpToolError(view).error).toMatchObject({
      code: "invalid_request",
      details: {
        operation: "inspect_analysis_view",
        issues: [expect.objectContaining({ path: ["source", "evidence_id"] })],
      },
    });

    const unselected = await runCli(cli, root, "trace-application-feature", {
      ...JAVASCRIPT_FEATURE_TRACE_EXAMPLE,
      application: { kind: "evidence-file", path: "sources.json" },
    });
    expect(unselected.exitCode).toBe(1);
    expect(unselected.json).toMatchObject({
      code: "invalid_request",
      details: {
        operation: "trace_application_feature",
        issues: [{ path: ["application", "evidence_id"] }],
      },
    });

    // A workflow that reads its sources unparsed still refuses a malformed reference as input.
    const malformed = await runCli(cli, root, "compare-application-versions", {
      left: JAVASCRIPT_APPLICATION_VERSION_COMPARISON_EXAMPLE.left,
      right: { kind: "retained-evidence" },
    });
    expect(malformed.exitCode).toBe(1);
    expect(malformed.json).toMatchObject({
      code: "invalid_request",
      details: {
        operation: "compare_application_versions",
        issues: [expect.objectContaining({ path: ["right", "evidence_id"] })],
      },
    });
  },
);

cliTest(
  "refuses one managed member record named on both sides in any source form",
  async ({ cli }) => {
    const { root, bundle } = await writeSources("rea-evidence-duplicates-");
    const call = await sharedMcp(cli);
    const imported = await call("import_evidence_bundle", { path: bundle });
    expect(imported.isError, JSON.stringify(imported)).not.toBe(true);
    const record = MANAGED_MEMBER_COMPARISON_EXAMPLE.left;
    const { evidence_id } = record;
    // Distinctness is a fact about the resolved records, not the spellings.
    for (const [form, right] of [
      ["inline", record],
      ["retained", { kind: "retained-evidence", evidence_id }],
      [
        "file",
        { kind: "evidence-file", path: join(root, `${evidence_id}.json`) },
      ],
      ["bundle record", { kind: "evidence-file", path: bundle, evidence_id }],
    ] as const) {
      const reply = await call("compare_managed_members", {
        left: record,
        right,
      });
      expect(parseMcpToolError(reply).error, form).toMatchObject({
        code: "invalid_request",
        details: {
          operation: "compare_managed_members",
          issues: [
            {
              path: ["right"],
              reason: "invalid_value",
              message: "Managed member Evidence must be distinct",
            },
          ],
        },
      });
    }
  },
);
