# Xtensa ELF analysis through Ghidra

This lane extends native ELF analysis to `EM_XTENSA` targets, such as the
`build/<app>.elf` that ESP-IDF links for ESP32, ESP32-S2 and ESP32-S3. It does not
execute Xtensa code, read flash images or partition tables, or rehost firmware.
It addresses [#3483](https://github.com/morluto/rea/issues/3483) and follows the
lane shape of [RISC-V](ghidra-riscv.md) and [PowerPC](ghidra-ppc.md).

**This lane is unverified.** REA admits these images from header and
`.xtensa.info` declarations, with module tests only. No real-Ghidra lane verifies
functions, references or decompilation yet, and every result carries a limitation
that says so.

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
| ELF64                                                                              | refused; Ghidra 12.1.4 ships 32-bit Xtensa languages only                   |
| Big-endian                                                                         | refused; big-endian cores need separate verification                        |
| `ET_REL`, `ET_DYN`, other `e_type`                                                 | refused; the reason names relocatable, shared, or the numeric `e_type`      |
| `e_flags` bits outside `EF_XTENSA_MACH` (0xf), `XT_INSN` (0x100), `XT_LIT` (0x200) | refused with the offending bits named                                       |
| Non-zero `EF_XTENSA_MACH`                                                          | refused; binutils defines only `E_XTENSA_MACH` (0) and rejects other values |
| `ABI=1` (call0), as ESP8266 builds declare                                         | refused; call0 needs its own calling-convention selection and verification  |
| Another `ABI=` value                                                               | refused with the declared value                                             |
| No `.xtensa.info`, or no `ABI=` key                                                | refused; the windowed ABI is not inferred                                   |
| Unreadable or malformed `.xtensa.info`                                             | refused with the reason, for example no section table or a malformed note   |

ESP-IDF builds for ESP32, ESP32-S2 and ESP32-S3 declare `e_flags` 0x300 and
`ABI=0`. The header does not identify the core configuration, so this lane cannot
tell an ESP32 from another Xtensa core with the same declarations. REA reads at
most 4096 bytes of `.xtensa.info`; binutils writes 56.

## Why the language is pinned

In the Ghidra 12.1.4 sources, `xtensa.ldefs` defines `Xtensa:LE:32:default` and
`Xtensa:BE:32:default`, each with one compiler specification whose id is
`default`; there is no `gcc` id. The default prototype in `xtensa.cspec` models
windowed calls, and `xtensa.opinion` maps ELF machine 94 to this processor. Header
selection should therefore choose the same language, but REA does not rely on
that. It pins `Xtensa:LE:32:default`
with `default`, records `language_selection: provider-pinned-v1`, and checks that
the import reports that language and compiler specification. A session that
reports anything else fails instead of returning results.

A caller-selected `REA_GHIDRA_LANGUAGE_ID` or `REA_GHIDRA_COMPILER_SPEC_ID` that
disagrees with the pin is a configuration error, and the requested settings are
not changed. A selection that matches the pin is recorded as `configured-v1`.

## Evidence

The lane identity is `elf32-le-exec-windowed-generic-v1`, and `xtensa_elf` retains
`elf_class`, `byte_order`, `type`, the raw `flags` and the declared `abi`. These
fields report what the image declares. They are not evidence of the core
configuration, the compiler, or instruction conformance.

## Ghidra limitations

These limitations belong to Ghidra 12.1.4, and REA does not work around them.
REA has not reproduced any of them. Each is either reported in an upstream
Ghidra issue or derived from the 12.1.4 Xtensa language sources:

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
- Reported upstream, and absent from the 12.1.4 sources: `SALT` and `SALTU`
  decode as bad instructions
  ([#9095](https://github.com/NationalSecurityAgency/ghidra/issues/9095)).
- Reported upstream: the relocation handler does not implement some types, such
  as `R_XTENSA_SLOT0_OP` and `R_XTENSA_ASM_EXPAND`, which ESP32 Wi-Fi and PHY
  libraries use ([#7341](https://github.com/NationalSecurityAgency/ghidra/issues/7341)).

## Verification and limits

Module tests cover the header gate, the `.xtensa.info` reader, the pin, the
post-import language check and every refusal. No `verify:ghidra:xtensa` lane
exists yet, so real Ghidra behavior on Xtensa images, including the quality of
windowed decompilation, is **not** established. Hopper, IDA and Kuna do not admit
Xtensa, and Windows Ghidra P0 refuses ELF targets.
