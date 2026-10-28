# Xtensa ELF analysis through Ghidra

This lane extends native ELF analysis to `EM_XTENSA` targets, such as the
`build/<app>.elf` that ESP-IDF links for ESP32, ESP32-S2 and ESP32-S3, and call0
ELF files such as ESP8266 builds; see [Call0 images](#call0-images). It does not
execute Xtensa code, read flash images or partition tables, or rehost firmware.
It addresses [#3483](https://github.com/morluto/rea/issues/3483) and follows the
lane shape of [RISC-V](ghidra-riscv.md) and [PowerPC](ghidra-ppc.md).
`npm run verify:ghidra:xtensa` checks it against Ghidra 12.1.4; see
[Verification and limits](#verification-and-limits).

## Admission boundary

ELF `EM_XTENSA` (94) is retained as the provider-neutral `xtensa` family, with the
raw ELF class, byte order, `e_type` and `e_flags`. The legacy `EM_XTENSA_OLD`
machine (`0xabc7`) is not recognized. Headerless Xtensa images are not supported;
see the [raw-binary admission boundary](raw-binary.md).

Xtensa `e_flags` carry no ABI. GNU as and ld declare it in the `.xtensa.info`
section: one `Xtensa_Info` note whose descriptor reads
`USE_ABSOLUTE_LITERALS=0\nABI=0\n`, where `ABI=0` is the windowed ABI and `ABI=1`
is call0. REA reads that note during target resolution and records the
declaration. It never infers an ABI from the family name. Other keys, including
`USE_ABSOLUTE_LITERALS`, are not interpreted; ESP-IDF builds declare 0.

Provider selection returns the specific unsupported constraint rather than
guessing a compatible profile:

| Declaration                                                                        | Outcome                                                                     |
| ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Little-endian ELF32 `ET_EXEC`, known `e_flags`, `ABI=0` (windowed)                 | admitted, `Xtensa:LE:32:default` + `default`                                |
| The same with `ABI=1` (call0), as ESP8266 builds declare                           | admitted, the same language; REA assigns `__call0` after analysis           |
| ELF64                                                                              | refused; Ghidra 12.1.4 ships 32-bit Xtensa languages only                   |
| Big-endian                                                                         | refused; big-endian cores need separate verification                        |
| `ET_REL`, `ET_DYN`, other `e_type`                                                 | refused; the reason names relocatable, shared, or the numeric `e_type`      |
| `e_flags` bits outside `EF_XTENSA_MACH` (0xf), `XT_INSN` (0x100), `XT_LIT` (0x200) | refused with the offending bits named                                       |
| Non-zero `EF_XTENSA_MACH`                                                          | refused; binutils defines only `E_XTENSA_MACH` (0) and rejects other values |
| Another `ABI=` value                                                               | refused with the declared value                                             |
| No `.xtensa.info`, or no `ABI=` key                                                | refused; no ABI is inferred                                                 |
| Unreadable or malformed `.xtensa.info`                                             | refused with the reason, for example no section table or a malformed note   |

ESP-IDF builds for ESP32, ESP32-S2 and ESP32-S3 declare `e_flags` 0x300 and
`ABI=0`. The header does not identify the core configuration, so this lane cannot
tell an ESP32 from another Xtensa core with the same declarations. REA reads at
most 4096 bytes of `.xtensa.info`; binutils writes 56. The bound is fixed: this
release has no runtime override, and runtime analysis settings do not raise it.

## Why the language is pinned

In the Ghidra 12.1.4 sources, `xtensa.ldefs` defines `Xtensa:LE:32:default` and
`Xtensa:BE:32:default`, each with one compiler specification whose id is
`default`; there is no `gcc` id. The default prototype in `xtensa.cspec` models
windowed calls; the specification also defines a `__call0` prototype. `xtensa.opinion`
maps ELF machine 94 to this processor. Header
selection should therefore choose the same language, but REA does not rely on
that. It pins `Xtensa:LE:32:default`
with `default`, records `language_selection: provider-pinned-v1`, and checks that
the import reports that language and compiler specification. A session that
reports anything else fails instead of returning results.

A caller-selected `REA_GHIDRA_LANGUAGE_ID` or `REA_GHIDRA_COMPILER_SPEC_ID` that
disagrees with the pin is a configuration error, and the requested settings are
not changed. A selection that matches the pin is recorded as `configured-v1`. A
selection that names only `Xtensa:LE:32:default` keeps the `default` compiler
specification, so the import and the post-import check still commit to it.

## Call0 images

Under the call0 ABI, a callee preserves `a12`-`a15` and may change `a8`-`a11`.
Ghidra 12.1.4's default Xtensa prototype, `__stdcall`, lists `a0`, `a1`,
`a8`-`a11` and `t2`-`t7` as preserved instead, matching its window fixups, which
save registers in `t2`-`t7`. `xtensa.cspec` defines the call0 model as
`__call0`, with the same parameter and return registers, but a program cannot
make it the default: the Decompiler option "Prototype Evaluation" selects only
the model of the function being decompiled
(`ProgramCompilerSpec.getPrototypeEvaluationModel`).

For an image whose `.xtensa.info` declares `ABI=1`, REA therefore runs a script
after analysis that assigns `__call0` to every function, external function and
function definition, including the signatures Ghidra's DWARF analyzer marks
`__stdcall`. A call to such a function then has the call0 register effects. The
profile commits `xtensa_call0_prototype: call0-prototype-v1`, and the bridge
reports how many functions and function definitions use `__call0`; REA delivers
that count as a limitation. A session that does not report the prototype for a
call0 image, or reports it for a windowed image, fails before any analysis
result is returned. As for windowed images, the pinned language refuses a
caller-supplied existing Ghidra project.

Measured by REA: when a call0 caller keeps a value in `a12` across a call,
Ghidra 12.1.4 with the default prototype computes it into a variable before the
call. With `__call0` it folds the value into the expression that uses it, for
example `return iVar1 + param_1 + 5;` for the lane's fixture. Both forms compute
the same value; the fold shows that the decompiler treats `a12` as preserved.

Measured by REA: a call to an address with no function in the program keeps the
default prototype, even after REA assigns `__call0`. The lane's fixture calls
the mask-ROM address `0x40002000` through `callx0`, as ESP8266 code calls ROM
routines, and the value it keeps in `a12` is computed before that call. Derived
from the Ghidra 12.1.4 sources, not reproduced by REA: the same applies to a call
through an untyped function pointer, because Ghidra has no program option for the
model of a call it cannot resolve to a function or function definition.
Auto-analysis also runs with the default prototype, before REA assigns
`__call0`.

## Evidence

The lane identity is `elf32-le-exec-windowed-generic-v1`, or
`elf32-le-exec-call0-generic-v1` with `xtensa_call0_prototype` for call0 images,
and `xtensa_elf` retains `elf_class`, `byte_order`, `type`, the raw `flags` and
the declared `abi`. These fields report what the image declares. They are not
evidence of the core configuration, the compiler, or instruction conformance.

## Ghidra limitations

These limitations belong to Ghidra 12.1.4, and REA does not work around them.
REA reproduced the first one; each of the others is reported in an upstream
Ghidra issue or derived from the 12.1.4 Xtensa language sources:

- Measured by REA: `SALT` and `SALTU`, which ESP32-S3 builds use, decode as bad
  instructions, so disassembly stops there and later calls in the same function
  are missing
  ([#9095](https://github.com/NationalSecurityAgency/ghidra/issues/9095)).
- Reported upstream: decompiled output only approximates register-window rotation
  for `call4`, `call8`, `call12`, `entry` and `retw`
  ([Ghidra #2164](https://github.com/NationalSecurityAgency/ghidra/issues/2164)).
- Reported upstream: FLIX bundles are not decoded
  ([#6342](https://github.com/NationalSecurityAgency/ghidra/issues/6342)).
- Derived from the 12.1.4 sources, which define no `ee.*` instructions: ESP32-S3
  PIE vector instructions are not decoded.
- Reported upstream: zero-overhead loops are mis-modeled, so functions that use
  `loop`, `loopnez` or `loopgtz` can decompile incorrectly
  ([#9027](https://github.com/NationalSecurityAgency/ghidra/issues/9027)).
- Reported upstream: the relocation handler does not implement some types, such
  as `R_XTENSA_SLOT0_OP` and `R_XTENSA_ASM_EXPAND`, which ESP32 Wi-Fi and PHY
  libraries use ([#7341](https://github.com/NationalSecurityAgency/ghidra/issues/7341)).

## What to expect with ESP-IDF apps

REA measured these costs with Ghidra 12.1.4 on Linux x64, using ESP-IDF 5.5
application ELFs with DWARF: a 16 MB ESP32 build and a 48 MB ESP32-S3 build.
Times depend on the host.

- **Ask for summaries first.** With the default `complete` detail,
  `inspect_native_load_image` returned 0.66–1.5 MB, and its `raw_result`
  duplicated `normalized_result.observations`. `list_procedures` returned
  1.5–2.9 MB. With `detail: "summary"`, each returned 5.7–6.8 KB and retained
  the complete Evidence. Page that Evidence with `inspect_analysis_view`: kind
  `native-load-image` for mappings, entry points and the other load-image
  collections, and kind `native-inventory` for procedure, name and string lists.
  See [load-image summaries](ghidra-provider.md#loaded-addresses-and-file-offsets)
  and [inventory pages](mcp-contracts.md#tool-results).
- **Allow for a slow first query.** `open_binary` returned in about 5 s. The
  first query then ran Ghidra's import and analysis: 53–56 s for the ESP32 app
  and 112 s for the ESP32-S3 app. A client on the MCP SDK's default 60-second
  request timeout failed on the ESP32-S3 app, and its cancellation discarded the
  analysis. Send a progress token and reset the timeout on progress
  (`resetTimeoutOnProgress: true`), or set a longer timeout; see
  [Ghidra first-query deadlines](mcp-contracts.md#ghidra-first-query-deadlines-and-recovery).
- **Keep one MCP session.** Later queries in the same session took 16–527 ms.
  Each CLI command imports and analyzes the ELF again: `rea decompile` took
  about 54 s per call on the ESP32 app. `--snapshot` replays an exact repeat of
  [`rea analyze`](cli.md#save-and-reuse-analysis-snapshots), but a repeated
  `rea decompile --procedure app_main` with the same `--snapshot` ran the whole
  analysis again.

## Verification and limits

Run `npm run verify:ghidra:xtensa` with Ghidra 12.1.4, JDK 21+ and GNU or LLVM
`readelf` (`REA_XTENSA_READELF` selects one). The lane writes its base fixture
from annotated instruction bytes, so it needs no Xtensa compiler, and never
executes target code. It checks:

- the header, symbols and `.xtensa.info` ABI against `readelf`;
- the pinned language and compiler specification in every result;
- `entry`, `l32r`, `call8` and `retw.n` decoding, the `call8` target and the
  `l32r` literal reference;
- decompiled code that passes the literal through `call8` and returns the
  callee's result;
- CLI/MCP parity with output-schema validation, and snapshot save and reopen;
- header-mutated refusals (unknown flag bits, machine field, `ET_DYN`, `ABI=2`);
- unchanged source bytes and owned cleanup.

A second annotated fixture holds call0 code at ESP8266 IRAM addresses and
declares `ABI=1`. The lane checks its `.xtensa.info` ABI against `readelf`, the
call0 lane and committed prototype in every result and in a saved and reopened
snapshot, the reported prototype count, `l32r`, `call0`, `callx0` and `ret.n`
decoding, and the `__call0` calling convention that `analyze_function` reports.
In decompiled code the first caller must keep its `a12` value across `call0` to
the leaf and add it to the callee's result. The second caller makes the same
call through `callx0` to the mask-ROM address, where the program has no
function, and its `a12` value must still be computed before the call. The same
bytes declared `ABI=0` are the control: with the default prototype, both callers
must compute that value before the call.

With `REA_XTENSA_CC` set to an Espressif compiler such as
`xtensa-esp32-elf-gcc`, the lane also builds `tests/conformance/c/xtensa.c`. It
checks in decompiled code that the caller passes the global and 5 through
`call8` and returns the result, and that the callee returns `value * factor`
plus its `l32r` constant. The same compiler with `-mabi=call0` also builds
`tests/conformance/c/xtensa-call0.c`, and `REA_XTENSA_LX106_CC` builds it with an
ESP8266 compiler such as `xtensa-lx106-elf-gcc`. For each build the lane checks
that `readelf` and REA read `ABI=1`, that the caller passes `value ^ 0x5a` and 5
and adds `value ^ 0x5a` to the result without a copy made before the call, and
that `analyze_function` reports `__call0`.

The call0 lane ran on Linux x64 with Ghidra 12.1.4, JDK 21 and GNU readelf 2.44,
with `xtensa-esp32-elf-gcc` 14.2.0 (crosstool-NG esp-14.2.0_20251107) and
Debian's `xtensa-lx106-elf-gcc` 13.3.0 with binutils 2.44. These freestanding
fixtures are the only call0 code it examines: no ESP8266 SDK or Arduino build
and no firmware from a device.

REA also measured Ghidra 12.1.4 on ESP-IDF 5.5.2 `hello_world` builds (Espressif
GCC 14.2.0, default `-Og`), with Ghidra's DWARF analyzer disabled so that
signatures come from decompilation, and compared the results with DWARF:

| Image    | Functions found | DWARF direct call edges found | Decompiled parameter counts equal to DWARF |
| -------- | --------------- | ----------------------------- | ------------------------------------------ |
| ESP32    | 738 of 738      | 1376 of 1377                  | 653 of 709                                 |
| ESP32-S3 | 915 of 915      | 1559 of 1598                  | 802 of 881                                 |

On ESP32-S3, 36 of the 39 missed call edges are in functions that use `SALT` or
`SALTU`. Most parameter differences are one fewer parameter, such as an unused
interrupt-handler argument; 64-bit arguments decompile as two parameters. The
measurement does not compare argument values at each call site, and the images
are not committed.

Hopper, IDA and Kuna do not admit Xtensa, and Windows Ghidra P0 refuses ELF
targets.
