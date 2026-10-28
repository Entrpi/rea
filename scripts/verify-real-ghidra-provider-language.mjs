import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFile,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import {
  requireMcpOperationResult,
  requireMcpOutput,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

if (process.argv.length !== 2)
  throw new Error(
    "Usage: node scripts/verify-real-ghidra-provider-language.mjs",
  );
// Windows Ghidra P0 does not admit provider languages.
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "Provider-language verification requires a Linux or macOS Ghidra host.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to a bring-your-own Ghidra installation.",
  );
const exec = promisify(execFile);
const run = createVerifierRun();
const root = fileURLToPath(new URL("..", import.meta.url));
const ghidra = await realpath(process.env.GHIDRA_INSTALL_DIR);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Source-owned SuperH-4 little-endian image, loaded at 0x8c000000. A 16-byte
// header precedes the entry, so the base and the entry differ:
//   0x8c000000 "REA-F5 SH4 IMAGE"   header, never reached
//   0x8c000010 224f   sts.l  pr,@-r15
//   0x8c000012 03b0   bsr    sub (0x8c000012 + 4 + 3*2 = 0x8c00001c)
//   0x8c000014 0900   nop    (delay slot)
//   0x8c000016 264f   lds.l  @r15+,pr
//   0x8c000018 0b00   rts
//   0x8c00001a 0900   nop    (delay slot)
//   0x8c00001c 01e0   sub: mov #1,r0
//   0x8c00001e 0b00   rts
//   0x8c000020 0270   add    #2,r0 (delay slot), so sub returns 3
const sh4 = Buffer.concat([
  Buffer.from("REA-F5 SH4 IMAGE", "ascii"),
  Buffer.from("224f03b00900264f0b00090001e00b000270", "hex"),
]);
const SH4 = {
  provider: "ghidra",
  language_id: "SuperH4:LE:32:default",
  compiler_spec_id: "default",
};
// Source-owned 6809 image, big-endian, loaded at 0xe000:
//   0xe000 8601  lda  #$01
//   0xe002 8d01  bsr  sub (0xe004 + 1 = 0xe005)
//   0xe004 39    rts
//   0xe005 4c    sub: inca
//   0xe006 39    rts
const m6809 = Buffer.from("86018d01394c39", "hex");
const M6809 = {
  provider: "ghidra",
  language_id: "6809:BE:16:default",
  compiler_spec_id: "default",
};

await mkdir(join(root, "build"), { recursive: true });
const workspace = await mkdtemp(join(root, "build", "rea-language-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const sh4Path = join(workspace, "sh4.bin");
const m6809Path = join(workspace, "m6809.bin");
await writeFile(sh4Path, sh4);
await writeFile(m6809Path, m6809);
const entrypoint = join(root, "scripts", "rea.mjs");
const environment = (installDir) => ({
  ...process.env,
  GHIDRA_INSTALL_DIR: installDir,
  TMPDIR: runtime,
  TMP: runtime,
  TEMP: runtime,
  REA_LOG_LEVEL: "silent",
  REA_PROCESS_RUN_ID: run.run_id,
});
const report = {
  ok: false,
  mocked: false,
  lane: "ghidra-provider-language",
  host: process.platform,
};

// Stock languages that no architecture describes.
await withServer(ghidra, async ({ call, refuse, fail }) => {
  const opened = await call("open_binary", {
    path: sh4Path,
    format: "raw-binary",
    provider_language: SH4,
    base_address: "0x8c000000",
    entry_point: "0x8c000010",
    provider_id: "ghidra",
  });
  assert.equal(opened.architecture, null);
  assert.equal(opened.base_address, "0x8c000000");
  assert.equal(opened.entry_point, "0x8c000010");
  assert.deepEqual(opened.provider_language, {
    ...SH4,
    verification: "unverified",
  });
  const image = evidence(await call("inspect_native_load_image"), sh4);
  const loaded = image.normalized_result;
  assert.equal(loaded.status, "verified", JSON.stringify(loaded));
  assert.equal(loaded.layout, "segments");
  assert.equal(loaded.architecture, null);
  assert.equal(loaded.language_id, SH4.language_id);
  assert.equal(loaded.compiler_spec_id, "default");
  assert.deepEqual(loaded.entries, [
    { address: "0x8c000010", role: "entry", basis: "caller" },
  ]);
  assert.deepEqual(loaded.segments, [
    {
      name: loaded.segments[0].name,
      address: "0x8c000000",
      size: sh4.length,
      backing: { kind: "source-range", source: 0, offset: 0 },
    },
  ]);
  const parameters = image.analysis_profile.parameters;
  assert.equal(parameters.language_selection, "caller-provider-language-v1");
  assert.equal(parameters.processor_labels, "not-applied-v1");
  assert.equal(parameters.architecture, null);
  const definition = parameters.language_definition;
  assert.equal(definition.address_bits, 32);
  const languages = "Ghidra/Processors/SuperH4/data/languages";
  for (const [role, name] of [
    ["ldefs", "SuperH4.ldefs"],
    ["sla", "SuperH4_le.sla"],
    ["pspec", "SuperH4.pspec"],
    ["cspec", "SuperH4_le.cspec"],
  ]) {
    assert.equal(definition.files[role].path, `${languages}/${name}`);
    assert.equal(
      definition.files[role].sha256,
      sha256(await readFile(join(ghidra, languages, name))),
    );
  }
  assert.ok(
    image.limitations.some((text) => text.includes("verification: unverified")),
  );
  const memory = evidence(
    await call("read_bytes", { address: "0x8c000000", length: sh4.length }),
    sh4,
  );
  assert.equal(memory.normalized_result.bytes_hex, sh4.toString("hex"));
  const procedures = evidence(await call("list_procedures"), sh4);
  assert.deepEqual(
    procedures.normalized_result.map((procedure) => procedure.address).sort(),
    ["0x8c000010", "0x8c00001c"],
  );
  // Ghidra prefixes an instruction in a delay slot with "_".
  const sh4Mnemonics = {
    "0x8c000010": "sts.l",
    "0x8c000012": "bsr",
    "0x8c000014": "_nop",
    "0x8c000016": "lds.l",
    "0x8c000018": "rts",
    "0x8c00001a": "_nop",
    "0x8c00001c": "mov",
    "0x8c00001e": "rts",
    "0x8c000020": "_add",
  };
  const mnemonics = {};
  for (const address of Object.keys(sh4Mnemonics))
    mnemonics[address] = evidence(
      await call("inspect_native_instruction", { address }),
      sh4,
    ).normalized_result.mnemonic;
  assert.deepEqual(mnemonics, sh4Mnemonics);
  report.sh4_mnemonics = mnemonics;
  const call_ = evidence(
    await call("inspect_native_instruction", { address: "0x8c000012" }),
    sh4,
  ).normalized_result;
  assert.match(call_.mnemonic, /^bsr$/iu);
  assert.equal(call_.flow.kind, "call");
  assert.deepEqual(call_.flow.direct_destinations, ["0x8c00001c"]);
  const pseudo = evidence(
    await call("procedure_pseudo_code", { procedure: "0x8c00001c" }),
    sh4,
  );
  assert.match(pseudo.normalized_result, /return\s+(?:3|0x3)\s*;/u);
  report.sh4 = {
    sha256: sha256(sh4),
    base: "0x8c000000",
    entry: "0x8c000010",
    load_image: loaded.status,
    procedures: procedures.normalized_result.map((item) => item.address),
    call: call_.flow.direct_destinations,
    decompiled_return: "3",
  };
  await call("close_binary");
  const { stdout } = await exec(
    process.execPath,
    [
      entrypoint,
      "inspect-native-load-image",
      sh4Path,
      "--target-format",
      "raw-binary",
      "--ghidra-language-id",
      SH4.language_id,
      "--ghidra-compiler-spec-id",
      SH4.compiler_spec_id,
      "--base-address",
      "0x8c000000",
      "--entry-point",
      "0x8c000010",
      "--provider",
      "ghidra",
      "--json",
    ],
    { env: environment(ghidra), timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const cli = evidence(JSON.parse(stdout), sh4);
  assert.deepEqual(cli.normalized_result, loaded);
  assert.equal(cli.analysis_profile.digest, image.analysis_profile.digest);
  report.cli_mcp_load_image_parity = true;

  const opened6809 = await call("open_binary", {
    path: m6809Path,
    format: "raw-binary",
    provider_language: M6809,
    entry_point: "0xe000",
    provider_id: "ghidra",
  });
  assert.equal(opened6809.architecture, null);
  const image6809 = evidence(
    await call("inspect_native_load_image"),
    m6809,
  ).normalized_result;
  assert.equal(image6809.status, "verified", JSON.stringify(image6809));
  assert.equal(image6809.language_id, M6809.language_id);
  const procedures6809 = evidence(await call("list_procedures"), m6809);
  assert.deepEqual(
    procedures6809.normalized_result
      .map((procedure) => procedure.address)
      .sort(),
    ["0xe000", "0xe005"],
  );
  const m6809Mnemonics = {};
  for (const address of ["0xe000", "0xe002", "0xe004", "0xe005", "0xe006"])
    m6809Mnemonics[address] = evidence(
      await call("inspect_native_instruction", { address }),
      m6809,
    ).normalized_result.mnemonic.toLowerCase();
  assert.deepEqual(m6809Mnemonics, {
    "0xe000": "lda",
    "0xe002": "bsr",
    "0xe004": "rts",
    "0xe005": "inca",
    "0xe006": "rts",
  });
  report.m6809_mnemonics = m6809Mnemonics;
  const bsr = evidence(
    await call("inspect_native_instruction", { address: "0xe002" }),
    m6809,
  ).normalized_result;
  assert.equal(bsr.flow.kind, "call");
  assert.deepEqual(bsr.flow.direct_destinations, ["0xe005"]);
  report.m6809 = {
    sha256: sha256(m6809),
    entry: "0xe000",
    load_image: image6809.status,
    procedures: procedures6809.normalized_result.map((item) => item.address),
    call: bsr.flow.direct_destinations,
  };
  const session = await call("binary_session");

  // Refused before Ghidra starts; the live session stays.
  const refusals = [
    [
      {
        provider_language: M6809,
        base_address: "0x10000",
        entry_point: "0x10000",
      },
      /raw-binary mapping from 0x10000 to 0x10006 must fit in the 16-bit address size that 6809:BE:16:default declares/u,
    ],
    [
      {
        provider_language: M6809,
        base_address: "0xfffc",
        entry_point: "0xfffc",
      },
      /raw-binary mapping from 0xfffc to 0x10002 must fit in the 16-bit address size that 6809:BE:16:default declares/u,
    ],
    [
      {
        provider_language: { ...SH4, language_id: "Absent:LE:32:default" },
        entry_point: "0x0",
      },
      /Absent:LE:32:default is not a language defined by Ghidra 12\.1\.4/u,
    ],
    [
      {
        provider_language: { ...SH4, compiler_spec_id: "gcc" },
        entry_point: "0x0",
      },
      /compiler_spec_id must be one of SuperH4:LE:32:default's compiler specs: default, windows/u,
    ],
    [
      { provider_language: SH4, architecture: "arm", entry_point: "0x0" },
      /provider_language replaces architecture; omit architecture/u,
    ],
  ];
  for (const [selection, reason] of refusals) {
    await refuse(
      {
        path: m6809Path,
        format: "raw-binary",
        provider_id: "ghidra",
        ...selection,
      },
      reason,
    );
    const preserved = await call("binary_session");
    assert.equal(preserved.analysis_run.run_id, session.analysis_run.run_id);
  }
  await refuse(
    {
      path: m6809Path,
      format: "raw-binary",
      provider_language: M6809,
      entry_point: "0xe000",
    },
    /provider_id must select ghidra explicitly/u,
  );
  report.refused_before_launch = refusals.length + 1;
  await call("close_binary");

  // Refused at import: the definition loads, but its spaces do not qualify.
  // Ghidra starts with the first analysis call, so that call fails.
  for (const [language, compilerSpec, reason] of [
    ["z80:LE:16:default", "default", /loaded memory spaces \[ram, io\]/u],
    [
      "avr8:LE:16:default",
      "gcc",
      /default address space code that is not byte-addressed/u,
    ],
  ]) {
    await call("open_binary", {
      path: m6809Path,
      format: "raw-binary",
      provider_language: {
        provider: "ghidra",
        language_id: language,
        compiler_spec_id: compilerSpec,
      },
      entry_point: "0x0",
      provider_id: "ghidra",
    });
    await fail("list_procedures", {}, reason);
    await call("close_binary");
  }
  report.refused_at_import = ["z80:LE:16:default", "avr8:LE:16:default"];
});

// A community module changed in place under the same ID, in a disposable
// copy of the installation; GHIDRA_INSTALL_DIR itself is only read.
const copy = join(workspace, "ghidra");
await cp(ghidra, copy, {
  recursive: true,
  preserveTimestamps: true,
  verbatimSymlinks: true,
});
assert.notEqual(await realpath(copy), ghidra);
const stock = join(copy, "Ghidra/Processors/SuperH4/data/languages");
const module = join(copy, "Ghidra/Processors/ReaF5Community");
const community = join(module, "data/languages");
await mkdir(community, { recursive: true });
await writeFile(join(module, "Module.manifest"), "");
// Timestamps are kept, so Ghidra finds the compiled .sla current.
for (const name of [
  "SuperH4_le.sla",
  "SuperH4_le.slaspec",
  "SuperH4.sinc",
  "SuperH4.pspec",
  "SuperH4_le.cspec",
])
  await cp(join(stock, name), join(community, name), {
    preserveTimestamps: true,
  });
await writeFile(
  join(community, "ReaF5Community.ldefs"),
  `<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language processor="ReaF5SH4" endian="little" size="32" variant="community"
            version="1.0" slafile="SuperH4_le.sla" processorspec="SuperH4.pspec"
            id="ReaF5SH4:LE:32:community">
    <description>SuperH-4 little endian, installed as a community module</description>
    <compiler name="default" spec="SuperH4_le.cspec" id="default"/>
  </language>
</language_definitions>
`,
);
const COMMUNITY = {
  provider: "ghidra",
  language_id: "ReaF5SH4:LE:32:community",
  compiler_spec_id: "default",
};
const snapshot = join(workspace, "community.snapshot.json");
await withServer(copy, async ({ call, refuse }) => {
  const open = (extra = {}) =>
    call("open_binary", {
      path: sh4Path,
      format: "raw-binary",
      provider_language: COMMUNITY,
      base_address: "0x8c000000",
      entry_point: "0x8c000010",
      provider_id: "ghidra",
      ...extra,
    });
  const profile = async () => {
    const image = evidence(await call("inspect_native_load_image"), sh4);
    assert.equal(image.normalized_result.status, "verified");
    return image.analysis_profile;
  };
  await open();
  const before = await profile();
  const procedures = evidence(await call("list_procedures"), sh4);
  assert.deepEqual(
    procedures.normalized_result.map((procedure) => procedure.address).sort(),
    ["0x8c000010", "0x8c00001c"],
  );
  await call("close_binary", { snapshot_path: snapshot });
  // The same definition replays its snapshot.
  await open({ snapshot_path: snapshot });
  assert.equal((await profile()).digest, before.digest);
  await call("close_binary");
  const cspec = join(community, "SuperH4_le.cspec");
  const original = await readFile(cspec);
  await appendFile(cspec, "<!-- updated in place -->\n");
  await refuse(
    {
      path: sh4Path,
      format: "raw-binary",
      provider_language: COMMUNITY,
      base_address: "0x8c000000",
      entry_point: "0x8c000010",
      provider_id: "ghidra",
      snapshot_path: snapshot,
    },
    /profile_mismatch/u,
  );
  await open();
  const after = await profile();
  await call("close_binary");
  assert.notEqual(after.digest, before.digest);
  const files = (value) => value.parameters.language_definition.files;
  assert.notEqual(files(after).cspec.sha256, files(before).cspec.sha256);
  for (const role of ["ldefs", "sla", "pspec"])
    assert.equal(files(after)[role].sha256, files(before)[role].sha256);
  assert.notEqual(
    after.parameters.function_coordinate_context.mapping_sha256,
    before.parameters.function_coordinate_context.mapping_sha256,
  );
  await writeFile(cspec, original);
  await open();
  assert.equal((await profile()).digest, before.digest);
  await call("close_binary");
  report.community_module = {
    language_id: COMMUNITY.language_id,
    snapshot_replayed_before_change: true,
    snapshot_refused_after_change: true,
    profile_digest_changed: true,
    coordinate_context_changed: true,
    restored_definition_restores_identity: true,
  };
});

assert.deepEqual(await readFile(sh4Path), sh4);
assert.deepEqual(await readFile(m6809Path), m6809);
report.source_unchanged = true;
assert.deepEqual(
  await readdir(runtime),
  [],
  `Runtime resources survived server shutdown; retained workspace: ${workspace}`,
);
report.runtime_cleanup = "complete";
report.ok = true;
const verifierRun = await completeVerifierRun(run);
assert.equal(verifierRun.process_lineage.status, "verified");
assert.deepEqual(verifierRun.process_lineage.descendants, []);
// Keep the workspace for diagnosis unless verification and cleanup both pass.
await rm(workspace, { recursive: true, force: true });
process.stdout.write(
  JSON.stringify({ verifier_run: verifierRun, ...report }) + "\n",
);

/** Run one MCP server against an installation and close it afterwards. */
async function withServer(installDir, body) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env: environment(installDir),
    stderr: "pipe",
  });
  const client = new Client({
    name: "rea-real-provider-language-proof",
    version: "1",
  });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });
  const call = async (name, args = {}) => {
    const result = await client.callTool(
      { name, arguments: args },
      { timeout: 240000 },
    );
    if (["open_binary", "binary_session", "close_binary"].includes(name))
      return requireMcpOperationResult(result, name);
    return requireMcpOutput(result, name);
  };
  const fail = async (name, args, reason) => {
    const failed = await client.callTool(
      { name, arguments: args },
      { timeout: 240000 },
    );
    assert.equal(failed.isError, true, JSON.stringify(failed.content));
    assert.match(JSON.stringify(failed.content), reason);
    return failed;
  };
  const refuse = (args, reason) => fail("open_binary", args, reason);
  try {
    await client.connect(transport);
    await body({ call, refuse, fail });
    await client.ping();
  } catch (cause) {
    if (stderr) process.stderr.write(stderr);
    throw cause;
  } finally {
    try {
      await client.close();
    } finally {
      await transport.close();
    }
  }
}

function evidence(value, bytes) {
  const result = parseEvidence(value);
  assert.equal(result.subject.digest.sha256, sha256(bytes));
  // A provider language names no family.
  assert.equal(result.subject.architecture, null);
  assert.equal(result.subject.format, "raw-binary");
  return result;
}
