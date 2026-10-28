#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { parseAnalysisSnapshot } from "../dist/domain/analysisSnapshot.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { functionDossierSchema } from "../dist/domain/native/functionDossier.js";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import {
  assertXtensaCFixturePseudocode,
  assertXtensaCall0CFixturePseudocode,
  assertXtensaCall0FixtureInstructions,
  assertXtensaCall0FixturePseudocode,
  assertXtensaFixtureInstructions,
  assertXtensaFixturePseudocode,
  inspectXtensaReadelf,
  xtensaCall0KeptValue,
  XTENSA_COMPILER_SPEC,
  XTENSA_LANGUAGE,
} from "../tests/conformance/ghidra/xtensa-checks.mjs";
import {
  buildXtensaCFixture,
  buildXtensaCall0CFixture,
  mutateXtensaFixture,
  writeXtensaCall0Fixture,
  writeXtensaFixture,
  XTENSA_C_FIXTURE_VALUES,
  XTENSA_CALL0_C_FIXTURE_VALUES,
  XTENSA_CALL0_FIXTURE_INSTRUCTIONS,
  XTENSA_CALL0_FIXTURE_SYMBOLS,
  XTENSA_CALL0_FIXTURE_VALUES,
  XTENSA_FIXTURE_ADDEND,
  XTENSA_FIXTURE_INSTRUCTIONS,
  XTENSA_FIXTURE_LITERAL,
  XTENSA_FIXTURE_SYMBOLS,
} from "../tests/conformance/ghidra/xtensa-fixture.mjs";
import {
  mcpTextValue,
  requireMcpLifecycleResult,
  requireMcpOutput,
  requireMcpToolError,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Optional cross-target lane. No tool acquisition and no target execution.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-xtensa.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error("This optional lane requires a Linux/macOS Ghidra host.");
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error("Missing prerequisite: caller-supplied GHIDRA_INSTALL_DIR");
for (const key of ["REA_GHIDRA_LANGUAGE_ID", "REA_GHIDRA_COMPILER_SPEC_ID"])
  if (process.env[key] !== undefined)
    throw new Error(
      `Unset ${key}: this lane verifies provider-pinned selection.`,
    );
const installation = await inspectVerifierGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
assert.equal(installation.status, "available", JSON.stringify(installation));
assert.equal(installation.providerVersion, "12.1.4");

const execute = promisify(execFile);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-xtensa-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  GHIDRA_INSTALL_DIR: installation.installDir,
  JAVA_HOME: installation.javaHome,
};
for (const key of ["GHIDRA_HEADLESS_MAXMEM", "GHIDRA_MAXMEM"])
  if (process.env[key] !== undefined) env[key] = process.env[key];
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-xtensa-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
const hex = (value) => `0x${value.toString(16)}`;

const reports = [];
let failure;
try {
  await client.connect(transport);
  const catalog = await client.listTools();
  const ajv = new Ajv({ strict: false });
  addFormats(ajv);
  const validators = new Map();
  for (const tool of catalog.tools) {
    assert.ok(
      ajv.validateSchema(tool.outputSchema),
      `${tool.name}: invalid output schema`,
    );
    const existing =
      typeof tool.outputSchema.$id === "string"
        ? ajv.getSchema(tool.outputSchema.$id)
        : undefined;
    validators.set(tool.name, existing ?? ajv.compile(tool.outputSchema));
  }

  const fixture = await writeXtensaFixture(workspace);
  const names = Object.keys(XTENSA_FIXTURE_SYMBOLS);
  const independent = await inspectXtensaReadelf(fixture.path, names);
  for (const name of names)
    assert.equal(
      BigInt(independent.symbols[name]),
      BigInt(XTENSA_FIXTURE_SYMBOLS[name].address),
      `${name}: readelf disagrees with the fixture annotation`,
    );
  const resolved = await parseBinaryTarget(fixture.path);
  if (!resolved.ok) throw resolved.error;
  assert.equal(resolved.value.architecture, "xtensa");
  assert.equal(resolved.value.sha256, fixture.sha256);
  assert.deepEqual(
    resolved.value.xtensa,
    independent.xtensa,
    "REA ELF interpretation disagrees with readelf",
  );
  const symbol = (name) => hex(XTENSA_FIXTURE_SYMBOLS[name].address);
  const assertProfile = (profile, abi = "windowed") => {
    assert.equal(profile.provider.id, "ghidra");
    assert.equal(profile.provider.version, installation.providerVersion);
    const parameters = profile.parameters;
    assert.equal(parameters.language_id, XTENSA_LANGUAGE);
    assert.equal(parameters.compiler_spec_id, XTENSA_COMPILER_SPEC);
    assert.equal(parameters.language_selection, "provider-pinned-v1");
    assert.equal(
      parameters.xtensa_support_lane,
      `elf32-le-exec-${abi}-generic-v1`,
    );
    assert.equal(
      parameters.xtensa_call0_prototype,
      abi === "call0" ? "call0-prototype-v1" : undefined,
    );
    assert.deepEqual(parameters.xtensa_elf, {
      elf_class: 32,
      byte_order: "little",
      type: 2,
      flags: 0x300,
      abi,
    });
  };
  const assertEvidence = (evidence, sha256, abi) => {
    assert.equal(evidence.provider.id, "ghidra");
    assert.equal(evidence.subject.architecture, "xtensa");
    assert.equal(evidence.subject.digest.sha256, sha256);
    assertProfile(evidence.analysis_profile, abi);
  };
  // Results of the open target: its Evidence is checked against its ABI lane.
  let opened = { sha256: fixture.sha256, abi: "windowed" };
  const evidenceOf = async (name, args = {}) => {
    const reply = await client.callTool(
      { name, arguments: args },
      { timeout: 240000 },
    );
    const lifecycle = [
      "open_binary",
      "close_binary",
      "binary_session",
    ].includes(name);
    const admitted = lifecycle
      ? requireMcpLifecycleResult(reply, name)
      : parseEvidence(requireMcpOutput(reply, name));
    const textual = JSON.parse(mcpTextValue(reply));
    assert.ok(reply.structuredContent, `${name} omitted structured result`);
    const validate = validators.get(name);
    assert.ok(validate, `${name} missing from advertised catalog`);
    assert.ok(validate(textual), `${name}: ${JSON.stringify(validate.errors)}`);
    if (!lifecycle) assertEvidence(admitted, opened.sha256, opened.abi);
    return admitted;
  };
  const call = async (name, args = {}) => {
    const admitted = await evidenceOf(name, args);
    return ["open_binary", "close_binary", "binary_session"].includes(name)
      ? admitted
      : admitted.normalized_result;
  };
  const open = (path, sha256, abi = "windowed", extra = {}) => {
    opened = { sha256, abi };
    return call("open_binary", { path, provider_id: "ghidra", ...extra });
  };

  const openedTarget = await open(fixture.path, fixture.sha256);
  assert.equal(openedTarget.architecture, "xtensa");
  assert.equal(openedTarget.sha256, fixture.sha256);
  const image = await call("inspect_native_load_image");
  assert.equal(image.observations.language_id, XTENSA_LANGUAGE);
  assert.equal(image.observations.compiler_spec_id, XTENSA_COMPILER_SPEC);
  for (const source of image.observations.source_files) {
    assert.equal(source.original_sha256, fixture.sha256);
    assert.equal(source.modified_sha256, fixture.sha256);
  }
  const procedures = await call("list_procedures");
  for (const name of ["rea_xtensa_entry", "rea_xtensa_leaf"]) {
    const procedure = procedures.find((value) => value.value === name);
    assert.ok(procedure, `${name} missing from Ghidra inventory`);
    assert.equal(BigInt(procedure.address), BigInt(symbol(name)));
  }
  const instructions = {};
  for (const [name, address] of Object.entries(XTENSA_FIXTURE_INSTRUCTIONS))
    instructions[name] = await call("inspect_native_instruction", {
      address: hex(address),
    });
  assertXtensaFixtureInstructions(instructions, {
    leaf: symbol("rea_xtensa_leaf"),
    literal: symbol("rea_xtensa_literal"),
  });
  const mapping = await call("address_to_file_offset", {
    address: symbol("rea_xtensa_entry"),
  });
  const sourceBytes = await readFile(fixture.path);
  assert.equal(
    sourceBytes
      .subarray(mapping.file_offset, mapping.file_offset + 3)
      .toString("hex"),
    instructions.entry.bytes,
  );
  const literal = await call("read_bytes", {
    address: symbol("rea_xtensa_literal"),
    length: 4,
  });
  assert.equal(literal.bytes_hex, "78563412");
  const callees = await call("procedure_callees", {
    procedure: symbol("rea_xtensa_entry"),
  });
  assert.ok(
    callees.some(
      (address) => BigInt(address) === BigInt(symbol("rea_xtensa_leaf")),
    ),
    "call8 target missing from the entry callees",
  );
  const entryCode = await call("procedure_pseudo_code", {
    procedure: symbol("rea_xtensa_entry"),
  });
  const leafCode = await call("procedure_pseudo_code", {
    procedure: symbol("rea_xtensa_leaf"),
  });
  assertXtensaFixturePseudocode(entryCode, leafCode, {
    literal: XTENSA_FIXTURE_LITERAL,
    addend: XTENSA_FIXTURE_ADDEND,
  });
  const dossier = functionDossierSchema.parse(
    await call("analyze_function", {
      procedure: symbol("rea_xtensa_entry"),
      detail: "complete",
    }),
  );
  assert.equal(dossier.pseudocode, entryCode);

  const refusals = [];
  for (const [change, reason] of [
    [{ flags: 0x700 }, "(0x400)"],
    [{ flags: 0x301 }, "machine 1"],
    [{ type: 3 }, "shared and position-independent"],
    [{ abi: "2" }, "ABI=2"],
  ]) {
    // Header-mutated copies test admission; they are not new producer claims.
    const rejectedPath = join(workspace, `refused-${refusals.length}.elf`);
    await writeFile(rejectedPath, mutateXtensaFixture(sourceBytes, change));
    const reply = await client.callTool(
      {
        name: "open_binary",
        arguments: { path: rejectedPath, provider_id: "ghidra" },
      },
      { timeout: 60000 },
    );
    const error = requireMcpToolError(reply);
    assert.ok(JSON.stringify(error).includes(reason), JSON.stringify(error));
    await assert.rejects(
      execute(
        process.execPath,
        [
          entrypoint,
          "function",
          rejectedPath,
          "rea_xtensa_entry",
          "--provider",
          "ghidra",
          "--json",
        ],
        { env, timeout: 60000, maxBuffer: 1024 * 1024 },
      ),
      (cause) =>
        Number.isInteger(cause.code) &&
        cause.code !== 0 &&
        `${cause.stdout}\n${cause.stderr}`.includes(reason),
    );
    refusals.push({ change, reason });
  }

  const snapshotPath = join(workspace, "xtensa.snapshot.json");
  const saved = await call("close_binary", { snapshot_path: snapshotPath });
  assert.ok(saved.evidence_records > 0);
  const snapshot = parseAnalysisSnapshot(
    JSON.parse(await readFile(snapshotPath, "utf8")),
  );
  assert.equal(snapshot.target.architecture, "xtensa");
  assert.equal(snapshot.target.sha256, fixture.sha256);
  assertProfile(snapshot.binding.analysis_profile);
  for (const record of snapshot.evidence_bundle.records)
    assertEvidence(parseEvidence(record), fixture.sha256);
  await open(fixture.path, fixture.sha256, "windowed", {
    snapshot_path: snapshotPath,
  });
  assert.deepEqual(await call("list_procedures"), procedures);
  await call("close_binary");

  for (const { command, operands } of [
    { command: "search", operands: ["rea_xtensa_", "--kind", "procedures"] },
    { command: "function", operands: ["rea_xtensa_entry"] },
  ]) {
    const cli = await execute(
      process.execPath,
      [
        entrypoint,
        command,
        fixture.path,
        ...operands,
        "--provider",
        "ghidra",
        "--json",
      ],
      { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
    );
    const evidence = parseEvidence(JSON.parse(cli.stdout));
    assertEvidence(evidence, fixture.sha256);
    if (command === "search")
      for (const name of ["rea_xtensa_entry", "rea_xtensa_leaf"])
        assert.ok(
          evidence.normalized_result.some((value) => value.value === name),
        );
    else {
      const cliDossier = functionDossierSchema.parse(
        evidence.normalized_result,
      );
      assert.equal(cliDossier.procedure.address, dossier.procedure.address);
      assert.equal(cliDossier.pseudocode, dossier.pseudocode);
    }
  }
  assert.equal(
    createHash("sha256")
      .update(await readFile(fixture.path))
      .digest("hex"),
    fixture.sha256,
  );
  reports.push({
    fixture: "annotated-instruction-bytes",
    sha256: fixture.sha256,
    independent_reader: {
      command: independent.command,
      version: independent.version,
    },
    language: XTENSA_LANGUAGE,
    procedures: procedures.length,
    checks: [
      "readelf header, symbols and Xtensa_Info ABI",
      "pinned language and compiler identity",
      "entry, l32r, call8 and retw.n decoding",
      "decompiled call8 argument is the l32r literal; caller returns the callee result",
      "decompiled leaf returns its argument plus the addend",
      "CLI/MCP parity with output-schema validation",
      "snapshot save and reopen",
      "header-mutated refusals",
    ],
    entry_pseudocode: entryCode,
    refusals,
    original_unchanged: true,
  });

  // call0: Ghidra's `__call0` prototype on every function. The same bytes
  // declared windowed are the control that shows what it changes.
  const call0Fixture = await writeXtensaCall0Fixture(workspace);
  const call0Names = Object.keys(XTENSA_CALL0_FIXTURE_SYMBOLS);
  const call0Readelf = await inspectXtensaReadelf(
    call0Fixture.path,
    call0Names,
  );
  for (const name of call0Names)
    assert.equal(
      BigInt(call0Readelf.symbols[name]),
      BigInt(XTENSA_CALL0_FIXTURE_SYMBOLS[name].address),
      `${name}: readelf disagrees with the call0 fixture annotation`,
    );
  const call0Target = await parseBinaryTarget(call0Fixture.path);
  if (!call0Target.ok) throw call0Target.error;
  assert.deepEqual(call0Target.value.xtensa, call0Readelf.xtensa);
  assert.equal(call0Readelf.xtensa.abi.abi, "call0");
  const call0Symbol = (name) => hex(XTENSA_CALL0_FIXTURE_SYMBOLS[name].address);
  await open(call0Fixture.path, call0Fixture.sha256, "call0");
  const call0Inventory = await evidenceOf("list_procedures");
  for (const name of ["rea_xtensa_call0_entry", "rea_xtensa_call0_leaf"])
    assert.ok(
      call0Inventory.normalized_result.some(
        (procedure) =>
          procedure.value === name &&
          BigInt(procedure.address) === BigInt(call0Symbol(name)),
      ),
      `${name} missing from Ghidra inventory`,
    );
  // The bridge reports the prototype outcome; the session delivers it.
  const outcome =
    /^Call0 prototype outcome: (\d+) functions and (\d+) function definitions use __call0\.$/u;
  const reported = call0Inventory.limitations
    .map((limitation) => outcome.exec(limitation))
    .filter((match) => match !== null);
  assert.equal(reported.length, 1, JSON.stringify(call0Inventory.limitations));
  assert.ok(Number(reported[0][1]) >= 2, reported[0][0]);
  const call0Instructions = {};
  for (const [name, address] of Object.entries(
    XTENSA_CALL0_FIXTURE_INSTRUCTIONS,
  ))
    call0Instructions[name] = await call("inspect_native_instruction", {
      address: hex(address),
    });
  assertXtensaCall0FixtureInstructions(call0Instructions, {
    leaf: call0Symbol("rea_xtensa_call0_leaf"),
    literal: call0Symbol("rea_xtensa_call0_literal"),
  });
  assert.ok(
    (
      await call("procedure_callees", {
        procedure: call0Symbol("rea_xtensa_call0_entry"),
      })
    ).some(
      (address) =>
        BigInt(address) === BigInt(call0Symbol("rea_xtensa_call0_leaf")),
    ),
    "call0 target missing from the entry callees",
  );
  const call0Code = {};
  for (const name of ["rea_xtensa_call0_entry", "rea_xtensa_call0_leaf"])
    call0Code[name] = await call("procedure_pseudo_code", {
      procedure: call0Symbol(name),
    });
  assertXtensaCall0FixturePseudocode(
    call0Code.rea_xtensa_call0_entry,
    call0Code.rea_xtensa_call0_leaf,
    XTENSA_CALL0_FIXTURE_VALUES,
  );
  const call0Dossier = functionDossierSchema.parse(
    await call("analyze_function", {
      procedure: call0Symbol("rea_xtensa_call0_entry"),
      detail: "complete",
    }),
  );
  assert.equal(call0Dossier.pseudocode, call0Code.rea_xtensa_call0_entry);
  assert.equal(call0Dossier.native_api?.calling_convention, "__call0");
  await call("close_binary");
  const call0Cli = parseEvidence(
    JSON.parse(
      (
        await execute(
          process.execPath,
          [
            entrypoint,
            "function",
            call0Fixture.path,
            "rea_xtensa_call0_entry",
            "--provider",
            "ghidra",
            "--json",
          ],
          { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
        )
      ).stdout,
    ),
  );
  assertEvidence(call0Cli, call0Fixture.sha256, "call0");
  assert.equal(
    functionDossierSchema.parse(call0Cli.normalized_result).pseudocode,
    call0Dossier.pseudocode,
  );
  const declaredWindowed = join(workspace, "call0-declared-windowed.elf");
  const controlBytes = mutateXtensaFixture(call0Fixture.bytes, { abi: "0" });
  await writeFile(declaredWindowed, controlBytes);
  await open(
    declaredWindowed,
    createHash("sha256").update(controlBytes).digest("hex"),
  );
  const controlCode = await call("procedure_pseudo_code", {
    procedure: call0Symbol("rea_xtensa_call0_entry"),
  });
  assert.equal(
    xtensaCall0KeptValue(controlCode, XTENSA_CALL0_FIXTURE_VALUES),
    "before-call",
    `the windowed default prototype no longer differs: ${controlCode}`,
  );
  await call("close_binary");
  assert.equal(
    createHash("sha256")
      .update(await readFile(call0Fixture.path))
      .digest("hex"),
    call0Fixture.sha256,
  );
  reports.push({
    fixture: "annotated-call0-bytes",
    sha256: call0Fixture.sha256,
    language: XTENSA_LANGUAGE,
    prototype_outcome: reported[0][0],
    checks: [
      "readelf header, symbols and Xtensa_Info ABI=1",
      "call0 lane and committed call0 prototype in every result",
      "l32r, call0 and ret.n decoding and the call0 target",
      "decompiled caller keeps its a12 value across call0 and adds it to the callee result",
      "analyze_function reports the __call0 calling convention",
      "CLI/MCP parity",
      "the same bytes declared windowed compute the a12 value before the call",
    ],
    entry_pseudocode: call0Code.rea_xtensa_call0_entry,
    declared_windowed_pseudocode: controlCode,
    original_unchanged: true,
  });

  // A compiled call0 fixture: from an ESP8266 compiler, or an ESP32 compiler
  // with -mabi=call0. Both declare ABI=1; only the first targets the LX106.
  const call0Builds = [];
  if (process.env.REA_XTENSA_LX106_CC !== undefined)
    call0Builds.push({
      fixture: "c-compiled-call0-lx106",
      compiler: process.env.REA_XTENSA_LX106_CC,
      flags: [],
    });
  if (process.env.REA_XTENSA_CC !== undefined)
    call0Builds.push({
      fixture: "c-compiled-call0-mabi",
      compiler: process.env.REA_XTENSA_CC,
      flags: ["-mabi=call0"],
    });
  for (const { fixture: label, compiler: command, flags } of call0Builds) {
    const built = await buildXtensaCall0CFixture(
      workspace,
      command,
      flags,
      `${label}.elf`,
    );
    const cNames = ["rea_xtensa_call0_c_entry", "rea_xtensa_call0_c_scale"];
    const readelf = await inspectXtensaReadelf(built.path, cNames);
    assert.equal(readelf.xtensa.abi.abi, "call0", `${label} declares call0`);
    const cTarget = await parseBinaryTarget(built.path);
    if (!cTarget.ok) throw cTarget.error;
    assert.deepEqual(cTarget.value.xtensa, readelf.xtensa);
    await open(built.path, built.sha256, "call0");
    const cProcedures = await call("list_procedures");
    for (const name of cNames)
      assert.ok(
        cProcedures.some(
          (procedure) =>
            procedure.value === name &&
            BigInt(procedure.address) === BigInt(readelf.symbols[name]),
        ),
        `${name} missing from Ghidra inventory`,
      );
    const decompiled = {};
    for (const name of cNames)
      decompiled[name] = await call("procedure_pseudo_code", {
        procedure: readelf.symbols[name],
      });
    assertXtensaCall0CFixturePseudocode(
      decompiled.rea_xtensa_call0_c_entry,
      decompiled.rea_xtensa_call0_c_scale,
      XTENSA_CALL0_C_FIXTURE_VALUES,
    );
    const cDossier = functionDossierSchema.parse(
      await call("analyze_function", {
        procedure: readelf.symbols.rea_xtensa_call0_c_entry,
        detail: "complete",
      }),
    );
    assert.equal(cDossier.native_api?.calling_convention, "__call0");
    await call("close_binary");
    reports.push({
      fixture: label,
      sha256: built.sha256,
      toolchain: built.toolchain,
      flags: readelf.xtensa.flags,
      checks: [
        "readelf symbols and Xtensa_Info ABI=1",
        "call0 lane and committed call0 prototype",
        "decompiled caller passes value ^ 0x5a and 5, and adds value ^ 0x5a to the result without a pre-call copy",
        "analyze_function reports the __call0 calling convention",
      ],
      entry_pseudocode: decompiled.rea_xtensa_call0_c_entry,
      scale_pseudocode: decompiled.rea_xtensa_call0_c_scale,
    });
  }

  const compiler = process.env.REA_XTENSA_CC;
  if (compiler !== undefined) {
    const built = await buildXtensaCFixture(workspace, compiler);
    const cNames = ["rea_xtensa_c_entry", "rea_xtensa_c_scale"];
    const readelf = await inspectXtensaReadelf(built.path, cNames);
    const cTarget = await parseBinaryTarget(built.path);
    if (!cTarget.ok) throw cTarget.error;
    assert.deepEqual(cTarget.value.xtensa, readelf.xtensa);
    await open(built.path, built.sha256);
    const cProcedures = await call("list_procedures");
    for (const name of cNames)
      assert.ok(
        cProcedures.some(
          (procedure) =>
            procedure.value === name &&
            BigInt(procedure.address) === BigInt(readelf.symbols[name]),
        ),
        `${name} missing from Ghidra inventory`,
      );
    const cCallees = await call("procedure_callees", {
      procedure: readelf.symbols.rea_xtensa_c_entry,
    });
    assert.ok(
      cCallees.some(
        (address) =>
          BigInt(address) === BigInt(readelf.symbols.rea_xtensa_c_scale),
      ),
    );
    const decompiled = {};
    for (const name of cNames)
      decompiled[name] = await call("procedure_pseudo_code", {
        procedure: readelf.symbols[name],
      });
    assertXtensaCFixturePseudocode(
      decompiled.rea_xtensa_c_entry,
      decompiled.rea_xtensa_c_scale,
      XTENSA_C_FIXTURE_VALUES,
    );
    await call("close_binary");
    reports.push({
      fixture: "c-compiled",
      sha256: built.sha256,
      toolchain: built.toolchain,
      checks: [
        "readelf symbols",
        "call8 callee",
        "decompiled call8 arguments are the global and the factor; caller returns the callee result",
        "decompiled callee returns value * factor plus its l32r constant",
      ],
      entry_pseudocode: decompiled.rea_xtensa_c_entry,
      scale_pseudocode: decompiled.rea_xtensa_c_scale,
    });
  }
} catch (cause) {
  failure = cause;
}
for (const close of [() => client.close(), () => transport.close()]) {
  try {
    await close();
  } catch (cause) {
    failure = new AggregateError(
      failure === undefined ? [cause] : [failure, cause],
      "Verification or cleanup failed",
    );
  }
}
const completed = await completeVerifierRun(run);
if (
  completed.process_lineage.status !== "verified" ||
  completed.process_lineage.descendants.length !== 0
)
  throw new Error(`Cleanup unverified; retained workspace: ${workspace}`, {
    cause: failure,
  });
if (failure !== undefined)
  throw new Error(
    `Xtensa verification failed; retained workspace: ${workspace}; MCP stderr: ${stderr}`,
    { cause: failure },
  );
assert.deepEqual(
  await readdir(runtime),
  [],
  `Runtime resources survived server shutdown; retained workspace: ${workspace}`,
);
await rm(workspace, { recursive: true, force: true });
console.log(
  JSON.stringify(
    {
      verifier_run: completed,
      lane: "ghidra-xtensa",
      mocked: false,
      host: { platform: process.platform, architecture: process.arch },
      provider: { id: "ghidra", version: installation.providerVersion },
      c_fixture: process.env.REA_XTENSA_CC === undefined ? "skipped" : "built",
      lx106_fixture:
        process.env.REA_XTENSA_LX106_CC === undefined ? "skipped" : "built",
      fixtures: reports,
      cleanup: "complete",
    },
    null,
    2,
  ),
);
