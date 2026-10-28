import { describe, expect, it } from "vitest";
import {
  RISCV_ILP32_ABI,
  assertRiscvIlp32CallSites,
  assertRiscvIlp32Caller,
  assertRiscvIlp32Storage,
  assertRiscvIlp32TableConsistent,
  parseRiscvCallSites,
  riscvStorageLocations,
} from "./riscv-checks.mjs";

// `llvm-objdump -d --no-show-raw-insn` of rea_riscv_abi_caller in the soft-float
// fixture, built by LLVM 21 at -O0 (tabs and runs of spaces collapsed). The real
// lane disassembles its own build; this tests the oracle, not Ghidra.
const LISTING = `
113b4: addi sp, sp, -0xb0
113b6: sw ra, 0xac(sp)
113b8: sw s0, 0xa8(sp)
113ba: addi s0, sp, 0xb0
113bc: sw a0, -0xc(s0)
113c0: lw a2, -0xc(s0)
113c4: lui a0, 0x3fc00
113c8: lui a1, 0x40200
113cc: jal 0x110f4 <rea_riscv_abi_pick>
113ce: sw a0, -0x10(s0)
113d2: lw a2, -0xc(s0)
113d6: li a0, 0x0
113d8: sw a0, -0x9c(s0)
113dc: lui a1, 0x400a0
113e0: jal 0x11130 <rea_riscv_abi_wide>
113e2: lw a4, -0x9c(s0)
113e6: sw a1, -0x14(s0)
113ea: sw a0, -0x18(s0)
113ee: lw a0, -0xc(s0)
113f2: lui a2, 0x40130
113f6: lui a3, 0x40b00
113fa: lui a5, 0x40188
113fe: mv a1, a4
11400: jal 0x1117e <rea_riscv_abi_mixed>
11402: lw a7, -0x9c(s0)
11406: sw a1, -0x1c(s0)
1140a: sw a0, -0x20(s0)
1140e: lw a6, -0xc(s0)
11412: mv a1, sp
11414: lui a0, 0x401d0
11418: sw a0, 0x0(a1)
1141a: li a0, 0x1
1141c: li a1, 0x2
1141e: sw a1, -0xa0(s0)
11422: li a2, 0x3
11424: li a3, 0x4
11426: li a4, 0x5
11428: li a5, 0x6
1142a: jal 0x111e6 <rea_riscv_abi_split>
1142c: sw a1, -0x24(s0)
11430: sw a0, -0x28(s0)
11434: lui a0, 0x41080
11438: sw a0, -0x38(s0)
1143c: lui a0, 0x41180
11440: sw a0, -0x34(s0)
11444: lw a1, -0x34(s0)
11448: lw a0, -0x38(s0)
1144c: lui a2, 0x41280
11450: jal 0x11256 <rea_riscv_abi_pair>
11452: sw a1, -0x2c(s0)
11456: sw a0, -0x30(s0)
1145a: lui a0, 0x41380
1145e: sw a0, -0x48(s0)
11462: li a0, 0xc
11464: sw a0, -0x44(s0)
11468: lw a2, -0xc(s0)
1146c: lw a1, -0x44(s0)
11470: lw a0, -0x48(s0)
11474: jal 0x11296 <rea_riscv_abi_tagged>
11476: mv a2, a0
11478: lw a0, -0x9c(s0)
1147c: sw a2, -0xa4(s0)
11480: mv a2, a1
11482: lw a1, -0xa4(s0)
11486: sw a2, -0x3c(s0)
1148a: sw a1, -0x40(s0)
1148e: lui a1, 0x402b0
11492: sw a1, -0x74(s0)
11496: sw a0, -0x78(s0)
1149a: lui a1, 0x402d0
1149e: sw a1, -0x6c(s0)
114a2: sw a0, -0x70(s0)
114a6: lui a1, 0x41780
114aa: sw a1, -0x68(s0)
114ae: sw a0, -0x64(s0)
114b2: lw a0, -0x64(s0)
114b6: sw a0, -0x7c(s0)
114ba: lw a0, -0x68(s0)
114be: sw a0, -0x80(s0)
114c2: lw a0, -0x6c(s0)
114c6: sw a0, -0x84(s0)
114ca: lw a0, -0x70(s0)
114ce: sw a0, -0x88(s0)
114d2: lw a0, -0x74(s0)
114d6: sw a0, -0x8c(s0)
114da: lw a0, -0x78(s0)
114de: sw a0, -0x90(s0)
114e2: addi a0, s0, -0x60
114e6: addi a1, s0, -0x90
114ea: lui a2, 0x41840
114ee: jal 0x112d2 <rea_riscv_abi_large>
114f0: lw a0, -0xa0(s0)
114f4: lw a6, -0x9c(s0)
114f8: lw a4, -0xc(s0)
114fc: mv a2, sp
114fe: li a1, 0x13
11500: sw a1, 0x0(a2)
11502: lui a3, 0x40318
11506: lui a7, 0x40328
1150a: mv a2, a6
1150c: jal 0x11316 <rea_riscv_abi_variadic>
1150e: sw a0, -0x94(s0)
11512: lui a0, 0x12
11516: lw a3, 0x5a8(a0)
1151a: lw a2, -0xc(s0)
1151e: lui a0, 0x41a40
11522: lui a1, 0x41ac0
11526: jalr a3
11528: sw a0, -0x98(s0)
1152c: lw a0, -0x10(s0)
11530: lw a1, -0x14(s0)
11534: xor a0, a0, a1
11536: lw a1, -0x1c(s0)
1153a: xor a0, a0, a1
1153c: lw a1, -0x24(s0)
11540: xor a0, a0, a1
11542: lw a1, -0x30(s0)
11546: xor a0, a0, a1
11548: lw a1, -0x3c(s0)
1154c: xor a0, a0, a1
1154e: lw a1, -0x54(s0)
11552: xor a0, a0, a1
11554: lw a1, -0x94(s0)
11558: xor a0, a0, a1
1155a: lw a1, -0x98(s0)
1155e: xor a0, a0, a1
11560: lw ra, 0xac(sp)
11562: lw s0, 0xa8(sp)
11564: addi sp, sp, 0xb0
11566: ret
`;

// Ghidra 12.1.4 HighFunction prototypes of the LLVM 19 typed build, printed as
// `name return | parameter:type@storage`. DERIVED uses __rea_ilp32; DEFAULT is
// Ghidra's stock ilp32d prototype on the same image.
const DERIVED = `
rea_riscv_abi_pick float@a0:4 | a:float@a0:4 | b:float@a1:4 | sel:int@a2:4
rea_riscv_abi_wide double@a1:4,a0:4 | a:double@a1:4,a0:4 | sel:int@a2:4
rea_riscv_abi_mixed double@a1:4,a0:4 | i:int@a0:4 | d:double@a2:4,a1:4 | f:float@a3:4 | e:double@a5:4,a4:4
rea_riscv_abi_split double@a1:4,a0:4 | a:int@a0:4 | b:int@a1:4 | c:int@a2:4 | d:int@a3:4 | e:int@a4:4 | f:int@a5:4 | g:int@a6:4 | x:double@Stack[0x0]:4,a7:4
rea_riscv_abi_pair rea_riscv_abi_pair@a1:4,a0:4 | value:rea_riscv_abi_pair@a1:4,a0:4 | scale:float@a2:4
rea_riscv_abi_tagged rea_riscv_abi_tagged@a1:4,a0:4 | value:rea_riscv_abi_tagged@a1:4,a0:4 | tag:int@a2:4
rea_riscv_abi_large rea_riscv_abi_large *@a0:4 | __return_storage_ptr__:rea_riscv_abi_large *@a0:4 (auto) | value:rea_riscv_abi_large *@a1:4 | scale:float@a2:4
rea_riscv_abi_variadic uint@a0:4 | count:int@a0:4
`;
const DEFAULT_PICK =
  "rea_riscv_abi_pick float@fa0:4 | a:float@fa0:4 | b:float@fa1:4 | sel:int@a0:4";
const STRIPPED = `
rea_riscv_abi_pick undefined4@a0:4 | param_1:undefined4@a0:4 | param_2:undefined4@a1:4 | param_3:int@a2:4
rea_riscv_abi_wide undefined8@a1:4,a0:4 | param_1:undefined4@a0:4 | param_2:undefined4@a1:4 | param_3:int@a2:4
rea_riscv_abi_mixed undefined8@a1:4,a0:4 | param_1:int@a0:4 | param_2:undefined4@a1:4 | param_3:undefined4@a2:4 | param_4:undefined4@a3:4 | param_5:undefined4@a4:4 | param_6:undefined4@a5:4
rea_riscv_abi_split undefined8@a1:4,a0:4 | param_1:uint@a0:4 | param_2:uint@a1:4 | param_3:uint@a2:4 | param_4:uint@a3:4 | param_5:uint@a4:4 | param_6:uint@a5:4 | param_7:uint@a6:4 | param_8:undefined4@a7:4 | param_9:undefined4@Stack[0x0]:4
rea_riscv_abi_pair undefined8@a1:4,a0:4 | param_1:undefined4@a0:4 | param_2:undefined4@a1:4 | param_3:undefined4@a2:4
rea_riscv_abi_tagged undefined8@a1:4,a0:4 | param_1:undefined4@a0:4 | param_2:undefined4@a1:4 | param_3:undefined4@a2:4
rea_riscv_abi_large void@<VOID> | param_1:undefined4 *@a0:4 | param_2:undefined4 *@a1:4 | param_3:undefined4@a2:4
rea_riscv_abi_variadic uint@a0:4 | param_1:int@a0:4
`;

/** Rebuild inspect_native_api boundaries from the recorded prototype lines. */
const boundaries = (text: string, calling_convention = "__rea_ilp32") =>
  Object.fromEntries(
    text
      .trim()
      .split("\n")
      .map((line) => {
        const [head = "", ...parameters] = line.split(" | ");
        const name = head.slice(0, head.indexOf(" "));
        const [data_type, storage] = head.slice(name.length + 1).split("@");
        return [
          name,
          {
            calling_convention,
            return_type: { data_type, storage },
            parameters: parameters.map((parameter, ordinal) => {
              const at = parameter.indexOf(":");
              const [type, place] = parameter.slice(at + 1).split("@");
              return {
                ordinal,
                name: parameter.slice(0, at),
                data_type: type,
                storage: place,
              };
            }),
          },
        ];
      }),
  );

// Call lines of rea_riscv_abi_caller's pseudocode from the same Ghidra runs.
const TYPED_CALLER = `
  local_10 = rea_riscv_abi_pick(1.5,2.5,sel);
  local_18 = rea_riscv_abi_wide(3.25,local_c);
  local_20 = rea_riscv_abi_mixed(local_c,4.75,5.5,6.125);
  local_28 = rea_riscv_abi_split(1,2,3,4,5,6,local_c,7.25);
  local_30 = rea_riscv_abi_pair((rea_riscv_abi_pair)0x4118000041080000,10.5);
  local_40 = rea_riscv_abi_tagged((rea_riscv_abi_tagged)0xc41380000,local_c);
  rea_riscv_abi_large(&rStack_60,&local_90,16.5);
  uVar1 = rea_riscv_abi_variadic(2,0x13,0,0x40318000,local_c);
  fVar2 = (*rea_riscv_abi_callback)(20.5,21.5,local_c);
`;
const DEFAULT_CALLER = `
  fVar2 = rea_riscv_abi_pick(in_fa0,in_fa1,0x3fc00000);
  dVar3 = rea_riscv_abi_wide((double)CONCAT44(extraout_var,fVar2),0);
  (*rea_riscv_abi_callback)(extraout_fa0,extraout_fa1_00,0x41a40000);
`;
const STRIPPED_CALLER = `
  local_10 = FUN_ram_000110f4(0x3fc00000,0x40200000,param_1);
  local_18 = FUN_ram_00011130(0,0x400a0000,local_c);
  local_20 = FUN_ram_0001117e(local_c,0,0x40130000,0x40b00000,0,0x40188000);
  local_28 = FUN_ram_000111e6(1,2,3,4,5,6,local_c,0,0x401d0000);
  local_30 = FUN_ram_00011256(0x41080000,0x41180000,0x41280000);
  local_40 = FUN_ram_00011296(0x41380000,0xc,local_c);
  FUN_ram_000112d2(auStack_60,&local_90,0x41840000);
  uVar1 = FUN_ram_00011316(2,0x13,0,0x40318000,local_c);
  uVar2 = (*(code *)PTR_FUN_ram_000110f4_ram_00012598)
                    (0x41a40000,0x41ac0000,local_c,PTR_FUN_ram_000110f4_ram_00012598);
`;
const ADDRESSES = {
  rea_riscv_abi_pick: "0x110f4",
  rea_riscv_abi_wide: "0x11130",
  rea_riscv_abi_mixed: "0x1117e",
  rea_riscv_abi_split: "0x111e6",
  rea_riscv_abi_pair: "0x11256",
  rea_riscv_abi_tagged: "0x11296",
  rea_riscv_abi_large: "0x112d2",
  rea_riscv_abi_variadic: "0x11316",
};

describe("RISC-V ilp32 conformance checks", () => {
  it("keeps every call-site word at its storage location", () => {
    expect(() => assertRiscvIlp32TableConsistent()).not.toThrow();
    expect(riscvStorageLocations("Stack[0x0]:4,a7:4")).toEqual([
      "Stack[0x0]",
      "a7",
    ]);
    expect(riscvStorageLocations("a0:4 (auto)")).toEqual(["a0"]);
  });

  it("recovers the words the compiler's call sites write", () => {
    const calls = parseRiscvCallSites(LISTING);
    expect(calls.map((call) => call.target)).toEqual([
      "rea_riscv_abi_pick",
      "rea_riscv_abi_wide",
      "rea_riscv_abi_mixed",
      "rea_riscv_abi_split",
      "rea_riscv_abi_pair",
      "rea_riscv_abi_tagged",
      "rea_riscv_abi_large",
      "rea_riscv_abi_variadic",
      "indirect",
    ]);
    expect(() => assertRiscvIlp32CallSites(calls)).not.toThrow();
    // The variadic pairs skip a1, which still holds the stack argument.
    expect(calls[7]?.words).toMatchObject({
      a1: { word: 19 },
      a3: { word: 0x40318000 },
      a7: { word: 0x40328000 },
      "Stack[0x0]": { word: 19 },
    });
  });

  it("refuses a listing whose call site places a value elsewhere", () => {
    const moved = LISTING.replace("lui a1, 0x40200", "lui a2, 0x40200");
    expect(() => assertRiscvIlp32CallSites(parseRiscvCallSites(moved))).toThrow(
      /rea_riscv_abi_pick: a1/u,
    );
  });

  it("accepts the derived prototypes and refuses Ghidra's stock ilp32d model", () => {
    expect(() => assertRiscvIlp32Storage(boundaries(DERIVED))).not.toThrow();
    expect(() =>
      assertRiscvIlp32Storage(boundaries(STRIPPED), { stripped: true }),
    ).not.toThrow();
    expect(() =>
      assertRiscvIlp32Storage({
        ...boundaries(DERIVED),
        ...boundaries(DEFAULT_PICK),
      }),
    ).toThrow();
    expect(() =>
      assertRiscvIlp32Storage(boundaries(DERIVED, "__stdcall")),
    ).toThrow();
    expect(Object.keys(boundaries(DERIVED))).toEqual(
      Object.keys(RISCV_ILP32_ABI),
    );
  });

  it("reads the caller's arguments through the corrected storage", () => {
    expect(() => assertRiscvIlp32Caller(TYPED_CALLER, ADDRESSES)).not.toThrow();
    expect(() =>
      assertRiscvIlp32Caller(STRIPPED_CALLER, ADDRESSES, { stripped: true }),
    ).not.toThrow();
    expect(() => assertRiscvIlp32Caller(DEFAULT_CALLER, ADDRESSES)).toThrow();
    expect(() =>
      assertRiscvIlp32Caller(
        STRIPPED_CALLER.replace(
          "0x40130000,0x40b00000",
          "0x40b00000,0x40130000",
        ),
        ADDRESSES,
        { stripped: true },
      ),
    ).toThrow(/rea_riscv_abi_mixed call arguments/u);
  });
});
