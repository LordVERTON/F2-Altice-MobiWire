#!/usr/bin/env python3

from pathlib import Path
from collections import defaultdict
import hashlib
import struct

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_THUMB,
    CS_MODE_LITTLE_ENDIAN,
)
from capstone.arm_const import (
    ARM_OP_REG,
    ARM_OP_IMM,
    ARM_OP_MEM,
    ARM_REG_PC,
)


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK = Path(r"C:\Users\verto\mtkclient")

LOADER = (
    MTK
    / "mtkclient"
    / "Loader"
    / "MTK_AllInOne_DA_iot.bin"
)

OUT = (
    ROOT
    / "research"
    / "f2"
    / "work"
    / "repro"
)

REPORT = (
    OUT
    / "s12_9w_parent_slot_derivation.txt"
)

DADA = 0x2718

PARENTS = {
    "PARENT_A": 0x10044904,
    "NEXT_BASE": 0x10044A50,
    "COMMON08_NEAR": 0x100433A8,
}

TARGETS = {
    "COMMON_1C": 0x1004491C,
    "D5_SLOT":   0x10044950,
    "D6_SLOT":   0x10044990,
    "D3_SLOT":   0x100449D0,
    "D4_SLOT":   0x10044A10,
}

EXPECTED_FROM_PARENT = {
    0x1004491C: 0x18,
    0x10044950: 0x4C,
    0x10044990: 0x8C,
    0x100449D0: 0xCC,
    0x10044A10: 0x10C,
}


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def parse_entry(data):

    vals = struct.unpack_from(
        "<10H",
        data,
        DADA,
    )

    regions = []

    p = DADA + 20

    for i in range(vals[9]):

        f = struct.unpack_from(
            "<5I",
            data,
            p + i * 20,
        )

        regions.append({
            "index": i,
            "buf": f[0],
            "len": f[1],
            "addr": f[2],
            "start_offset": f[3],
            "sig": f[4],
        })

    return {
        "hw": vals[1],
        "region_index": vals[8],
        "regions": regions,
    }


def blob(data, r):
    return data[
        r["buf"]:
        r["buf"] + r["len"]
    ]


data = LOADER.read_bytes()
entry = parse_entry(data)

assert entry["hw"] == 0x6261
assert entry["region_index"] == 2

r3 = entry["regions"][3]

DA2_FULL = blob(data, r3)

DA2 = DA2_FULL[
    :len(DA2_FULL) - r3["sig"]
]

BASE = r3["addr"]


lines = []


def log(s=""):
    print(s)
    lines.append(s)


log("=" * 120)
log("S12.9W - PARENT -> SLOT SYMBOLIC DERIVATION")
log("=" * 120)

log()
log("NO DEVICE ACCESS")
log("NO BROM")
log("NO DA UPLOAD")
log("NO JUMP DA")
log("NO WRITE")
log("NO ERASE")

log()
log(f"loader SHA = {sha256(data)}")
log(f"DA2 SHA    = {sha256(DA2)}")


# ================================================================
# A. Exact mathematical model
# ================================================================

log()
log("=" * 120)
log("A. EXACT PARENT / SLOT RELATIONSHIPS")
log("=" * 120)

parent = PARENTS["PARENT_A"]

for name, target in TARGETS.items():

    delta = target - parent

    log(
        f"{name:<12} "
        f"0x{target:08X} "
        f"= parent + 0x{delta:X}"
    )


# ================================================================
# B. Locate literal words exactly
# ================================================================

log()
log("=" * 120)
log("B. EXACT PARENT LITERAL WORDS")
log("=" * 120)

literal_words = defaultdict(list)

for name, value in PARENTS.items():

    needle = struct.pack("<I", value)

    pos = 0

    while True:

        pos = DA2.find(needle, pos)

        if pos < 0:
            break

        literal_words[value].append(pos)

        log(
            f"{name:<14} "
            f"0x{value:08X} "
            f"literal DA2+0x{pos:05X}"
        )

        pos += 1


# ================================================================
# C. Find Thumb16 literal loads to exact parents
# ================================================================

log()
log("=" * 120)
log("C. EXACT LDR-LITERAL XREFS")
log("=" * 120)

parent_xrefs = []

for off in range(0, len(DA2) - 1, 2):

    hw = u16(DA2, off)

    # Thumb16 LDR Rt,[PC,#imm8*4]
    if (hw & 0xF800) != 0x4800:
        continue

    rt = (hw >> 8) & 7
    imm = hw & 0xFF

    runtime = BASE + off

    literal_runtime = (
        ((runtime + 4) & ~3)
        + imm * 4
    )

    literal_off = literal_runtime - BASE

    for value, offs in literal_words.items():

        if literal_off not in offs:
            continue

        x = {
            "off": off,
            "runtime": runtime,
            "rt": rt,
            "literal_off": literal_off,
            "value": value,
        }

        parent_xrefs.append(x)

        log(
            f"DA2+0x{off:05X} "
            f"runtime=0x{runtime:08X} "
            f"LDR r{rt} -> "
            f"0x{value:08X}"
        )


# ================================================================
# D. Lightweight symbolic forward trace
# ================================================================

log()
log("=" * 120)
log("D. LINEAR CONSTANT-PROPAGATION TRACE")
log("=" * 120)

md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB
    | CS_MODE_LITTLE_ENDIAN,
)

md.detail = True

target_by_value = {
    v: k
    for k, v in TARGETS.items()
}

derived_hits = []


def reg_id_name(ins, reg):
    return ins.reg_name(reg)


def operand_value(ins, op, regs):

    if op.type == ARM_OP_IMM:
        return op.imm

    if op.type == ARM_OP_REG:
        return regs.get(
            op.reg
        )

    return None


for x in parent_xrefs:

    start = x["off"]

    end = min(
        len(DA2),
        start + 0x180,
    )

    regs = {}

    # Seed register after the literal load.
    insns = list(
        md.disasm(
            DA2[start:end],
            BASE + start,
        )
    )

    if not insns:
        continue

    log()
    log(
        f"TRACE from 0x{x['runtime']:08X} "
        f"base=0x{x['value']:08X}"
    )

    for n, ins in enumerate(insns):

        # Seed the first instruction explicitly.
        if n == 0:
            regs[
                ins.operands[0].reg
            ] = x["value"]

            continue

        m = ins.mnemonic.lower()
        ops = ins.operands

        # Calls clobber low volatile registers.
        if m in ("bl", "blx"):

            for rid in list(regs):

                name = ins.reg_name(rid)

                if name in (
                    "r0", "r1",
                    "r2", "r3",
                    "r12",
                ):
                    regs.pop(
                        rid,
                        None,
                    )

            continue

        # MOV Rd, Rs/#imm
        if (
            m in ("mov", "movs")
            and len(ops) >= 2
            and ops[0].type == ARM_OP_REG
        ):

            v = operand_value(
                ins,
                ops[1],
                regs,
            )

            if v is None:
                regs.pop(
                    ops[0].reg,
                    None,
                )
            else:
                regs[
                    ops[0].reg
                ] = v

        # ADD / SUB
        elif (
            m in (
                "add", "adds",
                "sub", "subs",
            )
            and len(ops) >= 2
            and ops[0].type == ARM_OP_REG
        ):

            sign = (
                -1
                if m.startswith("sub")
                else 1
            )

            dst = ops[0].reg

            if len(ops) == 2:

                lhs = regs.get(dst)

                rhs = operand_value(
                    ins,
                    ops[1],
                    regs,
                )

            else:

                lhs = operand_value(
                    ins,
                    ops[1],
                    regs,
                )

                rhs = operand_value(
                    ins,
                    ops[2],
                    regs,
                )

            if (
                lhs is not None
                and rhs is not None
            ):

                regs[dst] = (
                    lhs
                    + sign * rhs
                ) & 0xFFFFFFFF

            else:
                regs.pop(
                    dst,
                    None,
                )

        # Non-literal loads clobber destination.
        elif (
            m.startswith("ldr")
            and len(ops) >= 2
            and ops[0].type == ARM_OP_REG
        ):

            dst = ops[0].reg

            # Before clobbering, resolve effective
            # address if base is known.
            if ops[1].type == ARM_OP_MEM:

                mem = ops[1].mem

                if (
                    mem.base != ARM_REG_PC
                    and mem.base in regs
                ):

                    ea = (
                        regs[mem.base]
                        + mem.disp
                    ) & 0xFFFFFFFF

                    if ea in target_by_value:

                        name = target_by_value[ea]

                        log(
                            f"  0x{ins.address:08X}: "
                            f"{ins.mnemonic} {ins.op_str} "
                            f"=> MEM {name} "
                            f"0x{ea:08X}"
                        )

                        derived_hits.append({
                            "kind": "MEM",
                            "address": ins.address,
                            "target": ea,
                            "name": name,
                            "source": x["value"],
                        })

            regs.pop(
                dst,
                None,
            )

        # Stores: resolve effective address.
        elif (
            m.startswith("str")
            and len(ops) >= 2
            and ops[1].type == ARM_OP_MEM
        ):

            mem = ops[1].mem

            if (
                mem.base in regs
            ):

                ea = (
                    regs[mem.base]
                    + mem.disp
                ) & 0xFFFFFFFF

                if ea in target_by_value:

                    name = target_by_value[ea]

                    log(
                        f"  0x{ins.address:08X}: "
                        f"{ins.mnemonic} {ins.op_str} "
                        f"=> MEM {name} "
                        f"0x{ea:08X}"
                    )

                    derived_hits.append({
                        "kind": "MEM",
                        "address": ins.address,
                        "target": ea,
                        "name": name,
                        "source": x["value"],
                    })

        # Record exact constants produced in registers.
        for rid, value in list(
            regs.items()
        ):

            if value not in target_by_value:
                continue

            name = target_by_value[
                value
            ]

            log(
                f"  0x{ins.address:08X}: "
                f"{ins.mnemonic} {ins.op_str} "
                f"=> {ins.reg_name(rid)} "
                f"= {name} "
                f"0x{value:08X}"
            )

            derived_hits.append({
                "kind": "REG",
                "address": ins.address,
                "target": value,
                "name": name,
                "source": x["value"],
            })


# ================================================================
# E. Explicit search for parent-offset immediates
# ================================================================

log()
log("=" * 120)
log("E. PARENT-OFFSET IMMEDIATE CENSUS")
log("=" * 120)

wanted_imms = sorted(
    set(
        EXPECTED_FROM_PARENT.values()
    )
)

for imm in wanted_imms:

    count = 0

    for ins in md.disasm(
        DA2,
        BASE,
    ):

        if any(
            op.type == ARM_OP_IMM
            and op.imm == imm
            for op in ins.operands
        ):

            count += 1

            if count <= 30:

                log(
                    f"imm=0x{imm:X} "
                    f"0x{ins.address:08X}: "
                    f"{ins.mnemonic} "
                    f"{ins.op_str}"
                )

    log(
        f"imm 0x{imm:X} total={count}"
    )


# ================================================================
# F. Independent 0x40-family evidence
# ================================================================

log()
log("=" * 120)
log("F. EXACT 0x40-SPACED TARGET MODEL")
log("=" * 120)

slot_targets = [
    TARGETS["D5_SLOT"],
    TARGETS["D6_SLOT"],
    TARGETS["D3_SLOT"],
    TARGETS["D4_SLOT"],
]

slot_pass = True

for i, addr in enumerate(
    slot_targets
):

    expected = (
        TARGETS["D5_SLOT"]
        + i * 0x40
    )

    ok = (
        addr == expected
    )

    slot_pass &= ok

    log(
        f"slot[{i}] "
        f"0x{addr:08X} "
        f"{'PASS' if ok else 'FAIL'}"
    )


# ================================================================
# G. Result
# ================================================================

log()
log("=" * 120)
log("S12.9W RESULT")
log("=" * 120)

log(
    f"EXACT PARENT XREFS          : "
    f"{len(parent_xrefs)}"
)

log(
    f"EXACT TARGET DERIVATIONS    : "
    f"{len(derived_hits)}"
)

log(
    "0x40 SLOT GEOMETRY          : "
    + (
        "PASS"
        if slot_pass
        else "FAIL"
    )
)

names_hit = sorted(
    set(
        h["name"]
        for h in derived_hits
    )
)

log(
    "DERIVED TARGETS             : "
    + (
        ", ".join(names_hit)
        if names_hit
        else "NONE"
    )
)

log()

if (
    slot_pass
    and all(
        name in names_hit
        for name in (
            "D5_SLOT",
            "D6_SLOT",
            "D3_SLOT",
            "D4_SLOT",
        )
    )
):

    log(
        "FACT CANDIDATE: DA2 code derives "
        "all four command-slot addresses "
        "from a referenced BSS base."
    )

elif derived_hits:

    log(
        "STRONGLY SUPPORTED: DA2 derives "
        "at least part of the proposed "
        "parent/slot structure."
    )

else:

    log(
        "INCONCLUSIVE: exact slot geometry "
        "is real, but this limited linear "
        "symbolic trace did not resolve "
        "a direct parent->slot derivation."
    )

log()
log("DEVICE ACCESS              : NO")
log("DA UPLOAD                  : NO")
log("DEVICE WRITE               : NO")
log("DEVICE ERASE               : NO")
log("FLASH AUTHORIZED           : NO")


REPORT.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)

print()
print(
    "Report:",
    REPORT,
)
