# ARM ELF analysis through Ghidra

This page covers 32-bit ARM ELF executables built for an M profile, such as STM32
and other Cortex-M firmware. It does not execute target code, emulate a reset
sequence, or rehost firmware. Headerless dumps use the
[raw-binary M-profile inputs](raw-binary.md#arm-m-profile-images) instead.

Ghidra 12.1.4 chooses the language of an ELF from its header. Its `ARM.opinion`
selects `ARM:LE:32:v8` for every little-endian `EM_ARM` image. That language's
default instruction state is ARM, it has no v8-M system registers such as
`MSPLIM`, and its processor specification names the A-profile exception vectors
at `0x0`. Ghidra decodes the entry, the functions that the ELF's symbols mark as
Thumb and the code they call correctly under either language, but code without
such a marker, such as a seeded vector handler, decodes in ARM state. M-profile
code runs only in Thumb state, so REA selects the M-profile decoder from the
image's build attributes.

## M-profile lane

The lane applies to an ARM ELF that is:

- a little-endian ELF32 `ET_EXEC` image;
- declared EABI version 5 in `e_flags`, without `EF_ARM_BE8`;
- an image whose `.ARM.attributes` file scope declares an M-profile architecture
  in `Tag_CPU_arch` with a variant in the table below.

| Tag_CPU_arch | Architecture       | Variant          | language_id        | Lane                                           |
| ------------ | ------------------ | ---------------- | ------------------ | ---------------------------------------------- |
| 11           | ARMv6-M            | `armv6-m`        | `ARM:LE:32:Cortex` | `elf32-exec-le-eabi5-armv6-m-pinned-v1`        |
| 12           | ARMv6S-M           | `armv6-m`        | `ARM:LE:32:Cortex` | `elf32-exec-le-eabi5-armv6-m-pinned-v1`        |
| 10           | ARMv7              | `armv7-m`        | `ARM:LE:32:Cortex` | `elf32-exec-le-eabi5-armv7-m-pinned-v1`        |
| 13           | ARMv7E-M           | `armv7e-m`       | `ARM:LE:32:Cortex` | `elf32-exec-le-eabi5-armv7e-m-pinned-v1`       |
| 16           | ARMv8-M Baseline   | `armv8-m.base`   | `ARM:LE:32:v8-m`   | `elf32-exec-le-eabi5-armv8-m.base-pinned-v1`   |
| 17           | ARMv8-M Mainline   | `armv8-m.main`   | `ARM:LE:32:v8-m`   | `elf32-exec-le-eabi5-armv8-m.main-pinned-v1`   |
| 21           | ARMv8.1-M Mainline | `armv8.1-m.main` | `ARM:LE:32:v8-m`   | `elf32-exec-le-eabi5-armv8.1-m.main-pinned-v1` |

The variants and their decoders are the
[raw-binary variants](raw-binary.md#arm-m-profile-images): one table maps each
profile to a Ghidra language for both kinds of input. The compiler
specification is `default`.

- ARMv7 spans the A, R and M profiles, so it selects `armv7-m` only with
  `Tag_CPU_arch_profile` M. The other architectures are M profiles; a profile
  other than M contradicts them.
- Ghidra 12.1.4 decodes the ARMv8.1-M low-overhead-loop branches `wls` and
  `le`, but gives `le` no fall-through, and their targets can be wrong, so code
  after such a loop can stay undisassembled, as for
  [raw images](raw-binary.md#limitations). `armv8.1-m.main` results say so.
- REA reads the public `aeabi` attributes of the file scope. It skips other
  vendors' subsections. Section and symbol scopes leave the declarations
  unknown.

REA pins the language with `-processor` and `-cspec`, records
`language_selection: provider-pinned-v1`, and checks the language that Ghidra
reports after import. Ghidra imports the ELF without its processor-defined
labels. `ARMCortex.pspec` names the vector table at `0x0`-`0x40` and marks every
handler slot an entry, reserved slots included, so in an image linked at `0x0`
its names would cover the table and the code after it. The ELF's own symbols
still name the handlers.

Every other ARM ELF keeps Ghidra's header-based language and the analysis
profile that it had before this lane. That includes A- and R-profile images,
images whose attributes are missing, unreadable or contradictory, and other load
shapes. When such an image declares an M profile, or REA
cannot read its attributes, the session states why the lane did not apply. No
ARM ELF that loaded before this lane is refused.

### Language override

A `REA_GHIDRA_LANGUAGE_ID` or `REA_GHIDRA_COMPILER_SPEC_ID` that you set still
wins over the M-profile pin, as for
[legacy MIPS images](ghidra-mips.md#admission-boundary). The profile then
records `language_selection: configured-v1` and is the same profile that the
override produced before this lane. The session states which language REA would
have pinned. The override is process-wide: unset it to let REA select the
decoder for each image.

## Floating-point calling convention

Ghidra's ARM compiler specification passes floating-point arguments and
results in VFP registers by default (`__stdcall`, AAPCS-VFP: `s0`-`s15` and
`d0`-`d7`). It also defines `__stdcall_softfp` for `-mfloat-abi=soft` and
`softfp`, which passes them in core registers. REA reads the image's float ABI
from the EABI5 float flags in `e_flags`, which linkers derive from every input,
and from `Tag_ABI_VFP_args` when the header declares none. The float ABI selects
the prototype that the DWARF analyzer gives the function signatures it imports:

| Float ABI    | Declaration                                                         | DWARF signatures   |
| ------------ | ------------------------------------------------------------------- | ------------------ |
| `vfp`        | `EF_ARM_ABI_FLOAT_HARD`, or `Tag_ABI_VFP_args` 1                    | default            |
| `base`       | `EF_ARM_ABI_FLOAT_SOFT`, or `Tag_ABI_VFP_args` 0                    | `__stdcall_softfp` |
| `compatible` | `Tag_ABI_VFP_args` 3: no floating-point value crosses an interface  | default            |
| `toolchain`  | `Tag_ABI_VFP_args` 2: a toolchain-specific convention               | default            |
| `unresolved` | both header flags, a reserved value, or an attribute that disagrees | default            |
| `undeclared` | neither the header nor the attributes                               | default            |

The lane verifies `vfp` passing with Ghidra's default prototype. For `base`
images, which `-mfloat-abi=soft` and `softfp` produce, REA sets the DWARF
analyzer's default calling convention to `__stdcall_softfp` before
auto-analysis. The signatures it imports then keep their `float` and `double`
types in `r0`-`r3`, and the lane checks that their decompiled code reads the
right argument. With the default prototype, those signatures would get VFP
storage. A float prototype from any other source keeps the default, and
parameters that Ghidra infers without a typed prototype stay in core registers.
A stripped image has no DWARF, so the setting does not apply to it. Images with
any other float ABI stay admitted under their lane, and the session carries a
limitation that names the declaration.

## Evidence and identity

A pinned lane adds these analysis-profile parameters:

- `language_id`, `compiler_spec_id` and `language_selection`;
- `arm_elf`: `elf_class`, `byte_order`, `type`, the raw `flags`, and
  `cpu_arch` and `cpu_arch_profile` as declared (`cpu_arch_profile` is the
  character code, 77 for M);
- `arm_support_lane`, the lane from the table above;
- `processor_labels: not-applied-v1`;
- for `base` images, `arm_float_prototype: dwarf-default-stdcall-softfp-v1`.

These parameters change the profile identity of M-profile ARM ELF images. Their
earlier sessions and snapshots no longer match and are not reused; the saved
Evidence stays readable. Every other ARM ELF keeps its profile, so its sessions
and snapshots are reused as before. So does an M-profile image opened with a
caller-selected language other than the pinned one, because the lane does not
change that import.

## Verification and limits

Run `npm run verify:ghidra:cortex-m-elf` with Ghidra 12.1.4 PUBLIC, a 64-bit
JDK 21 or later, and LLVM with Arm targets (`clang`, `ld.lld` and
`llvm-readelf`). Select installed tools with `REA_CLANG`, `REA_LLD` and
`REA_LLVM_READELF` when they are not on `PATH`. The lane builds committed C and
assembly sources for each M profile, with soft-float and hard-float builds of
one source, and uses `llvm-readelf --arch-specific` as the attribute oracle. It
never executes target code; see [testing](testing.md).

The pin is an analysis convention, not proof of the producer. The decoder does
not refuse instructions that a smaller profile lacks, and floating-point,
TrustZone and memory-protection state are not modelled. Only the file's
segments are mapped; peripherals, system blocks and device memory maps are not
created.

## Decision record

This is decision D2 of the embedded-target work, raised on
[#1922](https://github.com/morluto/rea/pull/1922).

- **Choice.** An M-profile lane chosen from `.ARM.attributes`, with the
  raw-image mapping: `ARM:LE:32:Cortex` for v6-M, v6S-M, v7-M and v7E-M, and
  `ARM:LE:32:v8-m` for v8-M Baseline and Mainline and v8.1-M Mainline. One
  versioned lane per variant. The language is checked after import, and processor-defined labels
  are not applied. Every float ABI is admitted. `vfp` passing is verified with
  Ghidra's default prototype. For `base` images, the DWARF analyzer gives the
  signatures it imports Ghidra's own `__stdcall_softfp`, which the lane
  verifies. Other declarations carry a limitation. All other ARM ELFs keep
  header-based selection and their profile. A caller-selected language that
  names the pin keeps the lane; a different one wins over it, and the profile
  stays the one that language produced before the lane.
- **Alternatives.** Refusing M-profile or soft-float EABI images, as #1922 does
  for its A-profile lane, would turn STM32 ELFs that load today into refusals.
  Keeping automatic `ARM:LE:32:v8` keeps its ARM-state default and A-profile
  vector labels; the rows would become automatic with an expected language.
  Refusing an override that differs from the pin, as the RISC-V lane does, would
  refuse configurations that work today; switching costs one condition, and
  doing it after a release narrows the contract. Dropping the lane for a
  caller-selected language that names the pin would keep those sessions'
  earlier profile, but the same import would lose the lane's DWARF prototype.
  Folding ARMv8.1-M Mainline
  into the `armv8-m.main` lane would drop the declared architecture, and
  splitting it out later would change identity again. Leaving `base` images on
  the default prototype gives their DWARF signatures VFP storage, so decompiled
  code can read the wrong argument. Switching every function to
  `__stdcall_softfp` after analysis would also cover prototypes from other
  sources, but it repairs results instead of selecting the prototype that the
  DWARF analyzer uses. The header alone cannot establish the profile, and linked
  executables declare their attributes in the file scope.
- **Owner and consumers.** `src/domain/armBuildAttributes.ts` owns the tags
  REA reads, their mapping to variants and the float-ABI reading.
  `src/domain/architectureVariant.ts` owns the variant names, and
  `GHIDRA_VARIANT_LANGUAGES`, `GHIDRA_VARIANT_LIMITATIONS` and
  `ghidraVariantProcessorLabels` own the decoders, their limitations and the
  label policy. `GHIDRA_ARM_ELF_LANES`,
  `GHIDRA_ARM_ELF_DWARF_PROTOTYPES` and `GHIDRA_ARM_ELF_VERIFIED_FLOAT_ABIS` own
  the lanes. The target resolver reads the attributes. Consumers are the Ghidra
  profile, the provider client, its launcher and bridge, session limitations,
  and snapshots.
- **Costs of change.** Code: one row per variant or float ABI. Compatibility:
  `arm_elf`, `arm_float_prototype` and the lane ids are permanent once released,
  so a lane that changes its language, compiler specification, label policy or
  DWARF prototype ships as a new version.
  Migration: each change invalidates the sessions and snapshots of the M-profile
  images it affects. Verification: rerun `npm run verify:ghidra:cortex-m-elf`.
