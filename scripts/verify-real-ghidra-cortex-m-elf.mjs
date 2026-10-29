#!/usr/bin/env node
// Real-Ghidra lane for M-profile ARM ELF executables: each variant's pinned
// decoder, float passing, header-selected images, and the language override.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
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
import {
  GHIDRA_ARM_ELF_DWARF_PROTOTYPES,
  GHIDRA_ARM_ELF_LANES,
} from "../dist/ghidra/GhidraArmProfile.js";
import {
  GHIDRA_VARIANT_LANGUAGES,
  GHIDRA_VARIANT_LIMITATIONS,
} from "../dist/ghidra/GhidraRawBinaryLanguage.js";
import {
  buildCortexMElfFixtures,
  llvmFunctionInstructions,
} from "../tests/conformance/ghidra/cortex-m-elf-fixture.mjs";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import { sameThumbMnemonic } from "./lib/llvm-thumb-oracle.mjs";
import {
  mcpTextValue,
  requireMcpLifecycleResult,
  requireMcpOutput,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-cortex-m-elf.mjs");
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

const tools = {
  clang: process.env.REA_CLANG ?? "clang",
  lld: process.env.REA_LLD ?? "lld",
  strip: process.env.REA_LLVM_STRIP ?? "llvm-strip",
  readelf: process.env.REA_LLVM_READELF ?? "llvm-readelf",
  objdump: process.env.REA_LLVM_OBJDUMP ?? "llvm-objdump",
};
const execute = promisify(execFile);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-cortex-m-elf-proof-"));
const runtime = join(workspace, "runtime");
const fixtureDirectory = join(workspace, "fixtures");
await mkdir(runtime);
await mkdir(fixtureDirectory);
// Only named settings reach REA, so an exported override or session setting
// cannot change what this lane verifies.
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
const client = new Client({
  name: "rea-real-cortex-m-elf-proof",
  version: "1",
});
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});

const SOFT = 0x05000200;
const HARD = 0x05000400;
const BASE_STANDARD =
  /^The image declares the base procedure-call standard \(soft-float or softfp\)/u;
const PINNED = /^ARM ELF: \.ARM\.attributes declares .* so REA pins /u;
const NO_DWARF =
  /^The image carries no DWARF, so no signature uses __stdcall_softfp/u;
const LANE_NOTE = /^ARM ELF: /u;
// Variants whose decoder names MSPLIM, which ARMv8-M Mainline added.
const MSPLIM_VARIANTS = ["armv8-m.main", "armv8.1-m.main"];
// The ARMv8.1-M function with a WLS/LE low-overhead loop.
const LOOP_FUNCTION = "rea_cm_sum";

let validators;
const call = async (name, args, expected) => {
  const reply = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  const lifecycle = ["open_binary", "close_binary", "binary_session"].includes(
    name,
  );
  const admitted = lifecycle
    ? requireMcpLifecycleResult(reply, name)
    : parseEvidence(requireMcpOutput(reply, name));
  const validate = validators.get(name);
  assert.ok(validate, `${name} missing from advertised catalog`);
  assert.ok(
    validate(JSON.parse(mcpTextValue(reply))),
    `${name}: ${JSON.stringify(validate.errors)}`,
  );
  if (!lifecycle && expected !== undefined) {
    assert.equal(admitted.subject.digest.sha256, expected.sha256);
    // Provider operations may commit their own options, but the import lane
    // stays the session's; inspect_native_api reports its workflow profile.
    if (name !== "inspect_native_api")
      for (const key of [
        "language_id",
        "language_selection",
        "arm_support_lane",
      ])
        assert.equal(
          admitted.analysis_profile.parameters[key],
          expected.parameters[key],
          `${name}: ${key}`,
        );
  }
  return admitted;
};

const reports = [];
let summary;
let failure;
try {
  await client.connect(transport);
  const ajv = new Ajv({ strict: false });
  addFormats(ajv);
  validators = new Map();
  for (const tool of (await client.listTools()).tools) {
    assert.ok(
      ajv.validateSchema(tool.outputSchema),
      `${tool.name}: invalid schema`,
    );
    const existing =
      typeof tool.outputSchema.$id === "string"
        ? ajv.getSchema(tool.outputSchema.$id)
        : undefined;
    validators.set(tool.name, existing ?? ajv.compile(tool.outputSchema));
  }
  const built = await buildCortexMElfFixtures(fixtureDirectory, tools);
  for (const fixture of built.fixtures) {
    const report = { name: fixture.name, variant: fixture.variant };
    for (const stripped of [false, true])
      report[stripped ? "stripped" : "unstripped"] = await verifyImage(
        fixture,
        stripped,
      );
    reports.push(report);
  }
  const hard = built.fixtures.find(({ name }) => name === "armv7e-m-hard");
  const identity = {
    ...(await verifyIdentity(hard)),
    ...(await verifyMatchingOverride(
      built.fixtures.find(({ name }) => name === "armv7e-m-soft"),
    )),
    ...(await verifySeededHandler(
      built.fixtures.find(({ name }) => name === "armv6-m-base0"),
    )),
  };
  summary = {
    lane: "ghidra-cortex-m-elf",
    mocked: false,
    host: { platform: process.platform, architecture: process.arch },
    provider: { id: "ghidra", version: installation.providerVersion },
    oracle: "llvm-readelf --arch-specific and llvm-objdump",
    compiler: built.compiler,
    source_sha256: built.source_sha256,
    vectors_sha256: built.vectors_sha256,
    fixtures: reports,
    identity,
    transport: { cli: true, stdio_mcp: true },
  };
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
    `Cortex-M ELF verification failed; retained workspace: ${workspace}; MCP stderr: ${stderr}`,
    { cause: failure },
  );
assert.deepEqual(
  (await readdir(runtime)).filter((name) => name.startsWith("rea-ghidra-")),
  [],
  `Owned Ghidra runtime survived close; retained workspace: ${workspace}`,
);
await rm(workspace, { recursive: true, force: true });
console.log(
  JSON.stringify(
    { verifier_run: completed, ...summary, cleanup: "complete" },
    null,
    2,
  ),
);

/** One image: REA's attribute reading, the lane, decoding and float passing. */
async function verifyImage(fixture, stripped) {
  const path = stripped ? fixture.stripped : fixture.path;
  const sha256 = stripped ? fixture.stripped_sha256 : fixture.sha256;
  const oracle = stripped ? fixture.stripped_readelf : fixture.readelf;
  // LLVM's reading of the declarations is the oracle for REA's reader.
  assert.equal(oracle.cpu_arch, fixture.cpuArch, fixture.name);
  assert.equal(oracle.flags, fixture.floatAbi === "hard" ? HARD : SOFT);
  assert.equal(oracle.vfp_args, fixture.floatAbi === "hard" ? 1 : null);
  const resolved = await parseBinaryTarget(path);
  if (!resolved.ok) throw resolved.error;
  assert.equal(resolved.value.sha256, sha256);
  assert.deepEqual(resolved.value.arm.attributes, {
    status: "declared",
    declarations: {
      cpuArch: oracle.cpu_arch,
      cpuArchProfile: oracle.cpu_arch_profile,
      vfpArgs: oracle.vfp_args,
    },
  });
  assert.equal(resolved.value.arm.flags, oracle.flags);

  const opened = await call("open_binary", { path, provider_id: "ghidra" });
  assert.equal(opened.architecture, "arm");
  assert.equal(opened.sha256, sha256);
  const procedures = await call("list_procedures", {});
  const profile = procedures.analysis_profile;
  const expected = { sha256, parameters: profile.parameters };
  const image = await call("inspect_native_load_image", {}, expected);
  const pinned = fixture.variant !== null;
  const language = pinned
    ? GHIDRA_VARIANT_LANGUAGES[fixture.variant]
    : "ARM:LE:32:v8";
  // The session's own readback of the imported language.
  assert.equal(image.normalized_result.observations.language_id, language);
  const lanes = procedures.limitations.filter((line) => LANE_NOTE.test(line));
  if (pinned) {
    assert.deepEqual(
      {
        language_id: profile.parameters.language_id,
        compiler_spec_id: profile.parameters.compiler_spec_id,
        language_selection: profile.parameters.language_selection,
        arm_support_lane: profile.parameters.arm_support_lane,
        processor_labels: profile.parameters.processor_labels,
        arm_elf: profile.parameters.arm_elf,
      },
      {
        language_id: language,
        compiler_spec_id: "default",
        language_selection: "provider-pinned-v1",
        arm_support_lane: GHIDRA_ARM_ELF_LANES[fixture.variant],
        processor_labels: "not-applied-v1",
        arm_elf: {
          elf_class: 32,
          byte_order: "little",
          type: 2,
          flags: oracle.flags,
          cpu_arch: oracle.cpu_arch,
          cpu_arch_profile: oracle.cpu_arch_profile,
        },
      },
    );
    assert.equal(lanes.length, 1);
    assert.match(lanes[0], PINNED);
    // What the variant's decoder gets wrong, as raw images of it state.
    for (const line of GHIDRA_VARIANT_LIMITATIONS[fixture.variant])
      assert.ok(procedures.limitations.includes(line), line);
    // soft and softfp both declare the base standard.
    assert.equal(
      procedures.limitations.some((line) => BASE_STANDARD.test(line)),
      fixture.floatAbi !== "hard",
    );
    // Only a stripped base-standard image leaves the DWARF prototype unused.
    assert.equal(
      procedures.limitations.some((line) => NO_DWARF.test(line)),
      fixture.floatAbi !== "hard" && stripped,
    );
  } else {
    // An A-profile image keeps Ghidra's header-based selection and profile.
    assert.equal(profile.parameters.language_id, "auto-from-header");
    assert.equal(profile.parameters.arm_support_lane, undefined);
    assert.deepEqual(lanes, []);
  }

  const listed = new Map(
    procedures.normalized_result.map((item) => [item.address, item]),
  );
  const symbols = fixture.symbols;
  assert.ok(listed.has(fixture.entry), `${fixture.name}: no entry function`);
  assert.ok(!listed.has(symbols.rea_cm_vectors), "Vector table is a function");
  const decoded = await verifyDecoding(fixture, path, expected, stripped);
  const floats = pinned
    ? await verifyFloatPassing(fixture, expected, listed, stripped)
    : undefined;
  await call("close_binary", {});
  assert.equal(
    createHash("sha256")
      .update(await readFile(path))
      .digest("hex"),
    sha256,
  );
  return {
    sha256,
    language_id: language,
    profile_digest: profile.digest,
    procedures: listed.size,
    vector_only_handler_is_function: listed.has(symbols.SysTick_Handler),
    decoded,
    ...(floats === undefined ? {} : { floats }),
    original_unchanged: true,
  };
}

/**
 * Ghidra decodes each checked function as LLVM does, in Thumb state for M
 * profiles. In a stripped image only code reached from the entry is checked:
 * nothing there names the vector-only handler, which the seed check covers.
 */
async function verifyDecoding(fixture, path, expected, stripped) {
  const checked = ["rea_cm_fpick", "rea_cm_dpick"];
  if (!stripped) checked.push("SysTick_Handler");
  if (fixture.variant !== null) checked.push("rea_cm_primask");
  if (MSPLIM_VARIANTS.includes(fixture.variant)) checked.push("rea_cm_msplim");
  if (fixture.variant === "armv8.1-m.main") checked.push(LOOP_FUNCTION);
  let instructions = 0;
  let loop;
  for (const symbol of checked) {
    // The stripped image keeps the layout, so the unstripped symbols address it.
    const listed = await llvmFunctionInstructions(
      tools.objdump,
      fixture.path,
      symbol,
    );
    // Each checked function returns with its last bx, or the loop function
    // with its pop; the alignment fill LLVM lists after it (mov r8,r8 or nop)
    // is not reached by any flow.
    const returns = symbol === LOOP_FUNCTION ? "pop" : "bx";
    const last = listed.findLastIndex(({ mnemonic }) => mnemonic === returns);
    assert.ok(last >= 0, `${fixture.name} ${symbol}: no ${returns}`);
    // Ghidra may leave the code after a low-overhead loop undisassembled, in
    // memory with no listed instruction, which it reports as not-in-listing.
    const loopEnd =
      symbol === LOOP_FUNCTION
        ? listed.findIndex(({ mnemonic }) => mnemonic === "le")
        : last;
    const unreached = [];
    for (const [index, { address, mnemonic }] of listed
      .slice(0, last + 1)
      .entries()) {
      const decoded = (
        await call("inspect_native_instruction", { address }, expected)
      ).normalized_result;
      if (index > loopEnd && decoded.status === "not-in-listing") {
        unreached.push(address);
        continue;
      }
      assert.equal(decoded.status, "decoded", JSON.stringify(decoded));
      assert.ok(
        sameThumbMnemonic(decoded.mnemonic, mnemonic),
        `${fixture.name}${stripped ? " stripped" : ""} ${address}: Ghidra ${decoded.raw_disassembly}, LLVM ${mnemonic}`,
      );
      if (fixture.variant !== null)
        assert.equal(
          decoded.decoder_context?.find(
            (context) => context.register === "TMode",
          )?.value,
          "1",
        );
      instructions += 1;
    }
    if (symbol === LOOP_FUNCTION)
      loop = {
        branches: await verifyLoopBranches(fixture, expected, listed),
        not_disassembled_after_loop: unreached,
      };
  }
  const raw = async (symbol) =>
    (
      await call(
        "inspect_native_instruction",
        { address: fixture.symbols[symbol] },
        expected,
      )
    ).normalized_result.raw_disassembly;
  if (fixture.variant !== null)
    assert.match(await raw("rea_cm_primask"), /\bprimask\b/iu);
  if (MSPLIM_VARIANTS.includes(fixture.variant))
    assert.match(await raw("rea_cm_msplim"), /\bmsplim\b/iu);
  return {
    functions: checked.length,
    instructions,
    ...(loop === undefined ? {} : { loop }),
  };
}

/**
 * Ghidra 12.1.4 gives LE no fall-through, and the targets of WLS and LE can
 * differ from LLVM's, which the results state. LE without a fall-through is
 * required, so that a change revisits that limitation; each branch's flow is
 * recorded with LLVM's target.
 */
async function verifyLoopBranches(fixture, expected, listed) {
  const branches = [];
  for (const { address, mnemonic, target } of listed) {
    if (mnemonic !== "wls" && mnemonic !== "le") continue;
    const evidence = await call(
      "inspect_native_instruction",
      { address },
      expected,
    );
    for (const line of GHIDRA_VARIANT_LIMITATIONS[fixture.variant])
      assert.ok(evidence.limitations.includes(line), line);
    const { raw_disassembly: disassembly, flow } = evidence.normalized_result;
    if (mnemonic === "le")
      assert.equal(flow.conditional, false, `${fixture.name}: LE flow`);
    branches.push({
      address,
      disassembly,
      llvm_target: target,
      conditional: flow.conditional,
      destinations: flow.direct_destinations,
    });
  }
  assert.equal(branches.length, 2, `${fixture.name}: WLS and LE`);
  return branches;
}

/**
 * Float passing in DWARF prototypes: Ghidra's default VFP prototype for a
 * hard-float image, and __stdcall_softfp, through the DWARF analyzer, for a
 * base-standard one. Stripped images have no DWARF; they are recorded only.
 */
async function verifyFloatPassing(fixture, expected, listed, stripped) {
  const observed = {};
  for (const symbol of ["rea_cm_fpick", "rea_cm_dpick"]) {
    const address = fixture.symbols[symbol];
    if (!listed.has(address)) continue;
    const boundary = (
      await call("inspect_native_api", { procedure: address }, expected)
    ).normalized_result.boundary;
    const code = (
      await call("procedure_pseudo_code", { procedure: address }, expected)
    ).normalized_result;
    observed[symbol] = {
      calling_convention: boundary.calling_convention,
      parameters: boundary.parameters.map(({ data_type, storage }) => ({
        data_type,
        storage,
      })),
      return: {
        data_type: boundary.return_type?.data_type ?? null,
        storage: boundary.return_type?.storage ?? null,
      },
      returns: /\breturn\s+(\w+)\s*;/u.exec(code)?.[1] ?? null,
    };
  }
  if (!stripped) {
    const [convention, floats, doubles] =
      fixture.floatAbi === "hard"
        ? ["__stdcall", ["s0:4", "s1:4", "s0:4"], ["d0:8", "d1:8", "d0:8"]]
        : [
            "__stdcall_softfp",
            ["r0:4", "r1:4", "r0:4"],
            ["r1:4,r0:4", "r3:4,r2:4", "r1:4,r0:4"],
          ];
    const passing = (type, [first, second, result]) => ({
      calling_convention: convention,
      parameters: [
        { data_type: type, storage: first },
        { data_type: type, storage: second },
      ],
      return: { data_type: type, storage: result },
      returns: "b",
    });
    // Each helper returns its second argument; the decompiled code must too.
    assert.deepEqual(observed.rea_cm_fpick, passing("float", floats));
    assert.deepEqual(observed.rea_cm_dpick, passing("double", doubles));
  }
  return observed;
}

/**
 * A stripped image's vector-only handler is a function only when something
 * names it. Seeded at its even code address, it decodes in Thumb state.
 */
async function verifySeededHandler(fixture) {
  const address = fixture.symbols.SysTick_Handler;
  const seeds = join(workspace, "handler-seeds.tsv");
  await writeFile(seeds, `${address}\tfunction\tSysTick_Handler\n`);
  const evidence = parseEvidence(
    JSON.parse(
      (
        await execute(
          process.execPath,
          [
            entrypoint,
            "decompile",
            fixture.stripped,
            "--procedure",
            address,
            "--provider",
            "ghidra",
            "--json",
          ],
          {
            env: { ...env, REA_GHIDRA_SEED_FILE: seeds },
            timeout: 240000,
            maxBuffer: 16 * 1024 * 1024,
          },
        )
      ).stdout,
    ),
  );
  assert.equal(
    evidence.analysis_profile.parameters.arm_support_lane,
    GHIDRA_ARM_ELF_LANES[fixture.variant],
  );
  assert.ok(
    evidence.limitations.some((line) =>
      line.startsWith("Seed outcome: 1 functions created"),
    ),
    JSON.stringify(evidence.limitations),
  );
  // rea_cm_ticks += 3u, decoded from Thumb code.
  assert.match(String(evidence.normalized_result), /\+\s*(?:3|0x3)\b/u);
  return { seeded_vector_handler_decodes_in_thumb: true };
}

/** Snapshot reuse, an override that wins over the pin, and CLI parity. */
async function verifyIdentity(fixture) {
  const expectedLanguage = GHIDRA_VARIANT_LANGUAGES[fixture.variant];
  const snapshotPath = join(workspace, "armv7e-m.snapshot.json");
  await call("open_binary", { path: fixture.path, provider_id: "ghidra" });
  const procedures = await call("list_procedures", {});
  const saved = await call("close_binary", { snapshot_path: snapshotPath });
  assert.ok(saved.evidence_records > 0);
  const snapshot = parseAnalysisSnapshot(
    JSON.parse(await readFile(snapshotPath, "utf8")),
  );
  assert.equal(snapshot.target.sha256, fixture.sha256);
  assert.equal(
    snapshot.binding.analysis_profile.parameters.arm_support_lane,
    GHIDRA_ARM_ELF_LANES[fixture.variant],
  );
  await call("open_binary", {
    path: fixture.path,
    provider_id: "ghidra",
    snapshot_path: snapshotPath,
  });
  assert.deepEqual(
    (await call("list_procedures", {})).normalized_result,
    procedures.normalized_result,
  );
  await call("close_binary", {});

  const pinned = await primaskThroughCli(fixture, {});
  assert.equal(
    pinned.analysis_profile.digest,
    procedures.analysis_profile.digest,
  );
  assert.equal(pinned.normalized_result.mnemonic, "mrs");
  // A caller-selected language other than the pin wins over it, and the
  // session says so.
  const override = "ARM:LE:32:v8-m";
  const configured = await primaskThroughCli(fixture, {
    REA_GHIDRA_LANGUAGE_ID: override,
  });
  assert.equal(configured.analysis_profile.parameters.language_id, override);
  assert.equal(
    configured.analysis_profile.parameters.language_selection,
    "configured-v1",
  );
  assert.equal(
    configured.analysis_profile.parameters.arm_support_lane,
    undefined,
  );
  assert.ok(
    configured.limitations.includes(
      `ARM ELF: the configured language ${override} replaces ${expectedLanguage}, which REA pins for the ${fixture.variant} profile that .ARM.attributes declares.`,
    ),
  );
  return {
    snapshot_replays_with_lane: true,
    cli_matches_mcp: true,
    different_override_wins: true,
  };
}

/** The primask read through the CLI, with extra REA settings. */
async function primaskThroughCli(fixture, environment) {
  return parseEvidence(
    JSON.parse(
      (
        await execute(
          process.execPath,
          [
            entrypoint,
            "inspect-native-instruction",
            fixture.path,
            fixture.symbols.rea_cm_primask,
            "--provider",
            "ghidra",
            "--json",
          ],
          {
            env: { ...env, ...environment },
            timeout: 240000,
            maxBuffer: 16 * 1024 * 1024,
          },
        )
      ).stdout,
    ),
  );
}

/**
 * A caller-selected language that names the pin keeps the lane, so a
 * base-standard image still gets the DWARF prototype; the session opens only
 * if the pre-script reports it.
 */
async function verifyMatchingOverride(fixture) {
  const language = GHIDRA_VARIANT_LANGUAGES[fixture.variant];
  const evidence = await primaskThroughCli(fixture, {
    REA_GHIDRA_LANGUAGE_ID: language,
  });
  const { parameters } = evidence.analysis_profile;
  assert.equal(parameters.language_id, language);
  assert.equal(parameters.language_selection, "configured-v1");
  assert.equal(
    parameters.arm_support_lane,
    GHIDRA_ARM_ELF_LANES[fixture.variant],
  );
  assert.equal(
    parameters.arm_float_prototype,
    GHIDRA_ARM_ELF_DWARF_PROTOTYPES.base.commitment,
  );
  assert.equal(evidence.normalized_result.mnemonic, "mrs");
  assert.ok(evidence.limitations.some((line) => PINNED.test(line)));
  assert.ok(evidence.limitations.some((line) => BASE_STANDARD.test(line)));
  assert.ok(
    !evidence.limitations.some((line) =>
      line.startsWith("ARM ELF: the configured language"),
    ),
    JSON.stringify(evidence.limitations),
  );
  return { matching_override_keeps_lane: true };
}
