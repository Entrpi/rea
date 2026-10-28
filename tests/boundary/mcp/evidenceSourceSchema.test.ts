import { tmpdir } from "node:os";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { McpServer } from "@modelcontextprotocol/server";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it } from "vitest";
import type { z } from "zod";

import { ARTIFACT_COMPARISON_EXAMPLE } from "../../../src/contracts/artifactComparisonExample.js";
import {
  JAVASCRIPT_FEATURE_TRACE_EXAMPLE,
  SOURCE_TO_BUNDLE_COMPARISON_EXAMPLE,
} from "../../../src/contracts/javascript/javascriptApplicationWorkflowExamples.js";
import { JAVASCRIPT_EXPORT_SHAPE_COMPARISON_EXAMPLE } from "../../../src/contracts/javascript/javascriptExportShapeComparisonExample.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { analysisInputErrorFromIssues } from "../../../src/domain/inputIssueProjection.js";
import { toolRegistrationOptions } from "../../../src/server/toolRegistrationOptions.js";
import { advertisedSchemaErrors } from "../../fixtures/mcpAdvertisedSchemaValidity.js";

const evidence = ARTIFACT_COMPARISON_EXAMPLE.left;
const retained = {
  kind: "retained-evidence",
  evidence_id: evidence.evidence_id,
} as const;
const file = {
  kind: "evidence-file",
  path: join(tmpdir(), "evidence.json"),
} as const;

/** Every tool that names Evidence with the shared source contract, and its source fields. */
const tools = [
  {
    contract: toolContract("compare_artifacts"),
    input: { left: retained, right: retained },
    sources: ["left", "right"],
  },
  {
    contract: toolContract("compare_functions"),
    input: { left: retained, right: retained },
    sources: ["left", "right"],
  },
  {
    contract: toolContract("compare_wasm_interfaces"),
    input: { left: retained, right: retained, scope: "both" },
    sources: ["left", "right"],
  },
  {
    contract: toolContract("trace_application_feature"),
    input: { ...JAVASCRIPT_FEATURE_TRACE_EXAMPLE, application: retained },
    sources: ["application"],
  },
  {
    contract: toolContract("trace_javascript_semantics"),
    input: {
      application: retained,
      query: {
        seed: { kind: "literal", value: true },
        direction: "backward-provenance",
      },
    },
    sources: ["application"],
  },
  {
    contract: toolContract("compare_application_versions"),
    input: { left: retained, right: retained },
    sources: ["left", "right"],
  },
  {
    contract: toolContract("compare_source_to_bundle"),
    input: { ...SOURCE_TO_BUNDLE_COMPARISON_EXAMPLE, application: retained },
    sources: ["application"],
  },
  {
    contract: toolContract("compare_javascript_export_shapes"),
    input: {
      ...JAVASCRIPT_EXPORT_SHAPE_COMPARISON_EXAMPLE,
      left: retained,
      right: retained,
    },
    sources: ["left", "right"],
  },
] as const;

/** One spelling per source form; the advertised schema rejects what the parser rejects. */
const sides: readonly (readonly [string, unknown, boolean])[] = [
  ["complete Evidence", evidence, true],
  ["retained reference", retained, true],
  ["Evidence file", file, true],
  [
    "selected bundle record",
    { ...file, evidence_id: evidence.evidence_id },
    true,
  ],
  ["second inline spelling", { kind: "inline", evidence }, false],
  ["retained reference without ID", { kind: "retained-evidence" }, false],
  ["two references at once", { ...retained, path: file.path }, false],
  [
    "Evidence carrying a source kind",
    { ...evidence, kind: "retained-evidence" },
    false,
  ],
  ["relative Evidence file", { ...file, path: "evidence.json" }, false],
  ["empty side", {}, false],
];

/** Malformed sources and the only issues each may report. */
const malformedSides: readonly (readonly [
  unknown,
  readonly (readonly [readonly string[], string])[],
])[] = [
  [
    { ...evidence, provider: { ...evidence.provider, name: 3 } },
    [[["provider", "name"], "invalid_type"]],
  ],
  [{ kind: "retained-evidence" }, [[["evidence_id"], "missing_argument"]]],
];

/** The projected issue paths and reasons a caller sees for one refused request. */
const refusalIssues = (
  contract: { readonly name: string; readonly inputSchema: z.ZodType },
  request: Readonly<Record<string, unknown>>,
) => {
  const parsed = contract.inputSchema.safeParse(request);
  if (parsed.success)
    throw new Error(`${contract.name} accepted ${JSON.stringify(request)}`);
  return analysisInputErrorFromIssues(
    contract.name,
    parsed.error.issues,
    request,
  ).issues.map(({ path, reason }) => [path, reason]);
};

it("advertises one source contract and rejects the same sources the parser rejects", async () => {
  const server = new McpServer({ name: "evidence-sources", version: "0" });
  const client = new Client({ name: "evidence-sources", version: "0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  for (const { contract } of tools)
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      async () => ({ content: [] }),
    );
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const { tools: advertised } = await client.listTools();
    expect(advertisedSchemaErrors(advertised)).toEqual([]);
    expect(
      advertised.find(({ name }) => name === "compare_artifacts")?.inputSchema
        .examples,
    ).toEqual([
      {
        left: {
          kind: "retained-evidence",
          evidence_id: ARTIFACT_COMPARISON_EXAMPLE.left.evidence_id,
        },
        right: {
          kind: "retained-evidence",
          evidence_id: ARTIFACT_COMPARISON_EXAMPLE.right.evidence_id,
        },
      },
    ]);
    for (const { contract, input, sources } of tools) {
      const tool = advertised.find(({ name }) => name === contract.name);
      if (tool === undefined)
        throw new Error(`${contract.name} not advertised`);
      const validate = new Ajv2020({
        strict: false,
        validateFormats: false,
      }).compile(tool.inputSchema);
      for (const field of sources) {
        const withoutSource = Object.fromEntries(
          Object.entries(input).filter(([key]) => key !== field),
        );
        const label = `${contract.name}.${field}`;
        expect(
          contract.inputSchema.safeParse(withoutSource).success,
          label,
        ).toBe(false);
        expect(validate(withoutSource), label).toBe(false);
        for (const [form, side, accepted] of sides) {
          const request = { ...input, [field]: side };
          expect(
            contract.inputSchema.safeParse(request).success,
            `${label}: ${form}`,
          ).toBe(accepted);
          expect(validate(request), `${label}: ${form}`).toBe(accepted);
        }
        // A malformed source reports only the issues of the form it names.
        for (const [side, issues] of malformedSides)
          expect(
            refusalIssues(contract, { ...input, [field]: side }),
            label,
          ).toEqual(issues.map(([path, reason]) => [[field, ...path], reason]));
      }
    }
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});
