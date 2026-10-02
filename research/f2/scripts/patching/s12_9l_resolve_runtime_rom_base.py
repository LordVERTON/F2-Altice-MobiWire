#!/usr/bin/env python3

from pathlib import Path
import hashlib
import struct

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_THUMB,
    CS_MODE_LITTLE_ENDIAN,
)


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

PKG = (
    MTK
    / "research" / "f2"
    / "data"
    / "firmware-packages"
    / "altice-service"
    / "altice_service_package"
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
    / "s12_9l_runtime_rom_base_audit.txt"
)

ROM_SHA = (
    "dbebc45c8e4334e61fd85bdab8988d4"
    "f271599263ce209520e36f571f3f4e37c"
)

TABLE_START = 0x3DB80
TABLE_END   = 0x3DC28
RECORD_SIZE = 0x0C

BASE_CANDIDATES = [
    0xF0370000,
    0xF0380000,
    0xF0390000,
    0xF03A0000,
]

D_COMMANDS = {
    0xF03ACA54: 0xD3,
    0xF03ACA5C: 0xD4,
    0xF03ACA64: 0xD5,
    0xF03ACA6C: 0xD6,
    0xF03ACA74: 0xD7,
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def u16(data, off):
    return struct.unpack_from(
        "<H",
        data,
        off,
    )[0]


def u32(data, off):
    return struct.unpack_from(
        "<I",
        data,
        off,
    )[0]


def p16(buf, off, value):
    struct.pack_into(
        "<H",
        buf,
        off,
        value & 0xFFFF,
    )


def p32(buf, off, value):
    struct.pack_into(
        "<I",
        buf,
        off,
        value & 0xFFFFFFFF,
    )


def parse_table(data):
    rows = []

    for off in range(
        TABLE_START,
        TABLE_END,
        RECORD_SIZE,
    ):
        if off + RECORD_SIZE > len(data):
            break

        target_lo = u32(
            data,
            off,
        )

        target_hi = u32(
            data,
            off + 4,
        )

        value = u32(
            data,
            off + 8,
        )

        target64 = (
            target_lo
            | (target_hi << 32)
        )

        rows.append({
            "record_off": off,
            "target_lo": target_lo,
            "target_hi": target_hi,
            "target": target64,
            "value": value,
        })

    return rows


def md_thumb():
    md = Cs(
        CS_ARCH_ARM,
        CS_MODE_THUMB
        | CS_MODE_LITTLE_ENDIAN,
    )

    md.detail = False
    md.skipdata = True

    return md


def disasm_at(data, file_off, runtime_addr, size=16):
    md = md_thumb()

    return list(
        md.disasm(
            data[
                file_off:
                min(
                    file_off + size,
                    len(data),
                )
            ],
            runtime_addr,
        )
    )


def is_branch(ins):
    m = ins.mnemonic.lower()

    return (
        m == "b"
        or m.startswith("b")
        and m not in (
            "bic",
            "bics",
        )
    )


def is_cond_branch(ins):
    m = ins.mnemonic.lower()

    return m in {
        "beq", "bne",
        "bcs", "bhs",
        "bcc", "blo",
        "bmi", "bpl",
        "bvs", "bvc",
        "bhi", "bls",
        "bge", "blt",
        "bgt", "ble",
    }


roms = list(
    PKG.rglob("ROM")
)

assert len(roms) == 1

ROM = roms[0]
rom = ROM.read_bytes()

assert sha256(rom) == ROM_SHA


import io
import contextlib

buf = io.StringIO()

with contextlib.redirect_stdout(buf):

    print("=" * 120)
    print("S12.9L - RESOLVE RUNTIME ROM BASE + PATCH WIDTH")
    print("=" * 120)

    print()
    print("NO DEVICE ACCESS")
    print("NO BROM")
    print("NO WRITE")
    print("NO ERASE")

    print()
    print(f"ROM size   : 0x{len(rom):X}")
    print(f"ROM SHA256 : {sha256(rom)}")
    print("ROM identity : PASS")


    # ==============================================================
    # A. Parse records as u64 target + u32 value
    # ==============================================================

    rows = parse_table(
        rom
    )

    print()
    print("=" * 120)
    print("A. PATCH TABLE AS <U64 TARGET, U32 VALUE>")
    print("=" * 120)

    print(
        f"record count = {len(rows)}"
    )

    all_hi_zero = True
    all_values_16 = True

    for i, r in enumerate(rows):

        hi_zero = (
            r["target_hi"] == 0
        )

        value16 = (
            r["value"] <= 0xFFFF
        )

        all_hi_zero &= hi_zero
        all_values_16 &= value16

        marker = ""

        if r["target"] in D_COMMANDS:
            marker = (
                f"  <<< CMD "
                f"0x{D_COMMANDS[r['target']]:02X}"
            )

        print(
            f"[{i:02d}] "
            f"ROM+0x{r['record_off']:05X} "
            f"target=0x{r['target']:016X} "
            f"value=0x{r['value']:08X}"
            f"{marker}"
        )

    print()
    print(
        "all target high dwords == 0 :",
        "PASS" if all_hi_zero else "FAIL",
    )

    print(
        "all patch values <= 0xFFFF :",
        "PASS" if all_values_16 else "FAIL",
    )


    # ==============================================================
    # B. Evaluate plausible 64 KiB-aligned runtime bases
    # ==============================================================

    print()
    print("=" * 120)
    print("B. RUNTIME BASE CANDIDATE SCORING")
    print("=" * 120)

    scored = []

    for base in BASE_CANDIDATES:

        print()
        print(
            f"--- BASE 0x{base:08X} ---"
        )

        all_in_range = True

        for r in rows:

            off = (
                r["target"]
                - base
            )

            if not (
                0 <= off
                and off + 4 <= len(rom)
            ):
                all_in_range = False

        print(
            "all targets map into ROM :",
            "PASS" if all_in_range else "FAIL",
        )

        if not all_in_range:
            continue


        patched = bytearray(
            rom
        )

        for r in rows:

            off = (
                r["target"]
                - base
            )

            # Primary hypothesis:
            # patch only the Thumb halfword.
            p16(
                patched,
                off,
                r["value"],
            )


        branch_count = 0
        cond_branch_count = 0
        exact_cmp_count = 0

        print()
        print("D3-D7 slots after 16-bit virtual patch:")

        for runtime, cmd in D_COMMANDS.items():

            off = (
                runtime
                - base
            )

            insns = disasm_at(
                patched,
                off,
                runtime,
                12,
            )

            print()
            print(
                f"runtime=0x{runtime:08X} "
                f"file=0x{off:X}"
            )

            for ins in insns[:5]:

                print(
                    f"  {ins.address:08X}: "
                    f"{ins.mnemonic:<8} "
                    f"{ins.op_str}"
                )

            if insns:

                first = insns[0]

                expected_imm = (
                    f"#0x{cmd:x}"
                )

                if (
                    first.mnemonic.lower()
                    == "cmp"
                    and "r1" in first.op_str.lower()
                    and expected_imm
                    in first.op_str.lower()
                ):
                    exact_cmp_count += 1

            # We expect a dispatcher to branch very soon
            # after each compare.
            for ins in insns[1:4]:

                if is_branch(ins):

                    branch_count += 1

                    if is_cond_branch(ins):
                        cond_branch_count += 1

                    break


        print()
        print(
            f"exact D3-D7 CMP count      : "
            f"{exact_cmp_count}/5"
        )

        print(
            f"nearby branch count        : "
            f"{branch_count}/5"
        )

        print(
            f"nearby conditional branches: "
            f"{cond_branch_count}/5"
        )

        score = (
            exact_cmp_count
            + branch_count * 3
            + cond_branch_count * 4
        )

        print(
            f"score = {score}"
        )

        scored.append(
            (
                score,
                cond_branch_count,
                branch_count,
                base,
            )
        )


    assert scored

    scored.sort(
        reverse=True
    )

    print()
    print("=" * 120)
    print("C. BASE RANKING")
    print("=" * 120)

    for (
        score,
        conds,
        branches,
        base,
    ) in scored:

        print(
            f"base=0x{base:08X} "
            f"score={score:3d} "
            f"branches={branches}/5 "
            f"conditional={conds}/5"
        )


    best = scored[0]

    best_score = best[0]
    best_base = best[3]

    unique_best = (
        len(scored) == 1
        or scored[0][0]
        > scored[1][0]
    )

    print()
    print(
        f"best base = "
        f"0x{best_base:08X}"
    )

    print(
        "unique best score :",
        "PASS" if unique_best else "NO",
    )


    # ==============================================================
    # D. Detailed mapping under best base
    # ==============================================================

    print()
    print("=" * 120)
    print("D. BEST-BASE PATCH TARGET MAP")
    print("=" * 120)

    for i, r in enumerate(rows):

        off = (
            r["target"]
            - best_base
        )

        old16 = u16(
            rom,
            off,
        )

        next16 = u16(
            rom,
            off + 2,
        )

        old32 = u32(
            rom,
            off,
        )

        print(
            f"[{i:02d}] "
            f"runtime=0x{r['target']:08X} "
            f"ROM+0x{off:05X} "
            f"old16=0x{old16:04X} "
            f"next16=0x{next16:04X} "
            f"old32=0x{old32:08X} "
            f"patch=0x{r['value']:04X}"
        )


    # ==============================================================
    # E. 16-bit vs 32-bit patch semantics
    # ==============================================================

    print()
    print("=" * 120)
    print("E. 16-BIT vs 32-BIT PATCH SEMANTICS")
    print("=" * 120)

    p16_image = bytearray(
        rom
    )

    p32_image = bytearray(
        rom
    )

    destroyed_nonzero_halfwords = 0

    for r in rows:

        off = (
            r["target"]
            - best_base
        )

        next_hw = u16(
            rom,
            off + 2,
        )

        if next_hw != 0:
            destroyed_nonzero_halfwords += 1

        p16(
            p16_image,
            off,
            r["value"],
        )

        p32(
            p32_image,
            off,
            r["value"],
        )

    print(
        "records whose following halfword "
        "would be zeroed by a 32-bit write :",
        destroyed_nonzero_halfwords,
        "/",
        len(rows),
    )


    for label, image in (
        ("16-BIT PATCH", p16_image),
        ("32-BIT PATCH", p32_image),
    ):

        print()
        print(
            f"--- {label} ---"
        )

        for runtime, cmd in D_COMMANDS.items():

            off = (
                runtime
                - best_base
            )

            insns = disasm_at(
                image,
                off,
                runtime,
                10,
            )

            print(
                f"CMD 0x{cmd:02X} "
                f"@ 0x{runtime:08X}"
            )

            for ins in insns[:4]:

                print(
                    f"  {ins.address:08X}: "
                    f"{ins.mnemonic:<8} "
                    f"{ins.op_str}"
                )


    # ==============================================================
    # F. Full reconstructed window, 16-bit hypothesis
    # ==============================================================

    print()
    print("=" * 120)
    print("F. RECONSTRUCTED RUNTIME WINDOW - 16 BIT PATCH")
    print("=" * 120)

    runtime_start = (
        min(
            r["target"]
            for r in rows
        )
        - 0x20
    )

    runtime_end = (
        max(
            r["target"]
            for r in rows
        )
        + 0x40
    )

    file_start = (
        runtime_start
        - best_base
    )

    file_end = (
        runtime_end
        - best_base
    )

    md = md_thumb()

    insns = list(
        md.disasm(
            p16_image[
                file_start:file_end
            ],
            runtime_start,
        )
    )

    for ins in insns:

        marker = ""

        if ins.address in D_COMMANDS:

            marker = (
                f"  <<< CMD "
                f"0x{D_COMMANDS[ins.address]:02X}"
            )

        print(
            f"{ins.address:08X}: "
            f"{ins.mnemonic:<10} "
            f"{ins.op_str}"
            f"{marker}"
        )


    # ==============================================================
    # G. D5 / D6 branch extraction
    # ==============================================================

    print()
    print("=" * 120)
    print("G. D5 / D6 LOCAL CONTROL FLOW")
    print("=" * 120)

    branch_targets = {}

    for runtime, cmd in (
        (0xF03ACA64, 0xD5),
        (0xF03ACA6C, 0xD6),
    ):

        off = (
            runtime
            - best_base
        )

        insns = disasm_at(
            p16_image,
            off,
            runtime,
            16,
        )

        print()
        print(
            f"COMMAND 0x{cmd:02X}"
        )

        target = None

        for ins in insns[:6]:

            print(
                f"  {ins.address:08X}: "
                f"{ins.mnemonic:<8} "
                f"{ins.op_str}"
            )

            if (
                ins.address != runtime
                and is_branch(ins)
            ):
                try:
                    target = int(
                        ins.op_str,
                        0,
                    )
                except Exception:
                    target = None

                if target is not None:
                    break

        branch_targets[
            cmd
        ] = target

        print(
            "  first branch target:",
            (
                f"0x{target:08X}"
                if target is not None
                else "UNKNOWN"
            ),
        )


    # ==============================================================
    # H. Classification
    # ==============================================================

    print()
    print("=" * 120)
    print("S12.9L RESULT")
    print("=" * 120)

    print(
        f"BEST ROM BASE             : "
        f"0x{best_base:08X}"
    )

    print(
        "BEST BASE UNIQUE          :",
        "PASS" if unique_best else "NO",
    )

    print(
        "ALL TABLE VALUES <=16 BIT :",
        "PASS" if all_values_16 else "FAIL",
    )

    print(
        "32-BIT PATCH WOULD ZERO "
        "FOLLOWING HALFWORDS       :",
        destroyed_nonzero_halfwords,
    )

    print()

    if (
        best_base == 0xF0370000
        and unique_best
    ):
        print(
            "STRONGLY SUPPORTED: "
            "ROM runtime base = 0xF0370000."
        )

    else:
        print(
            "ROM runtime base is not yet proven."
        )

    if (
        all_values_16
        and destroyed_nonzero_halfwords > 0
    ):
        print(
            "STRONGLY SUPPORTED: "
            "table applies 16-bit Thumb halfword patches."
        )

    print(
        "D5 first branch target :",
        (
            f"0x{branch_targets[0xD5]:08X}"
            if branch_targets[0xD5] is not None
            else "UNKNOWN"
        ),
    )

    print(
        "D6 first branch target :",
        (
            f"0x{branch_targets[0xD6]:08X}"
            if branch_targets[0xD6] is not None
            else "UNKNOWN"
        ),
    )

    print()
    print(
        "FLASH AUTHORIZED: NO"
    )


result = buf.getvalue()

print(
    result,
    end="",
)

REPORT.write_text(
    result,
    encoding="utf-8",
)

print()
print(
    "Report:",
    REPORT,
)
