#!/usr/bin/env python3
"""S13.5A.120: classify only A119 post-selection BLX and its first target.

STRICTLY OFFLINE: canonical ALICE/ZIMAGE files opened read-only; emits one
exclusive-create UTF-8 .txt; never accesses phone/USB/COM, patches binaries,
repackages firmware, edits emulators, or invokes a native audio callback.

A119 CPU evidence was selected index 1/r0=87ED/r1=2 and index 2/r0=8928/r1=4,
with 10342FDE BLX 102FD0A4. This script does NOT re-emulate that callback.
It independently decodes the exact callsite, ARM entry/possible literal veneer,
and bounded first instructions of a resolved mapped callee. No UI-OK claim.
"""
from __future__ import annotations
import argparse
import hashlib
import struct
import sys
from pathlib import Path

ALICE_BASE=0x1024EC00
ALICE_SIZE=0x157BB4
ALICE_SHA="7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE=0xF023CA50
ZIMAGE_SIZE=0x185E98
ZIMAGE_SHA="85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
CALLSITE=0x10342FDE
ARM_ENTRY=0x102FD0A4
SELECT_CB=0x10342FC4
SELECT_STORE=0x10342FDC
REPORT="s13_5a120_post_select_blx_veneer_target_audit.txt"
PREFIX_MAX_INSTRUCTIONS=36


def abort(message):
    raise RuntimeError("A120_ABORT: "+message)


def img_read(blob: bytes, base: int, va: int, size: int) -> bytes:
    offset=va-base
    if size < 0 or offset < 0 or offset+size > len(blob):
        abort(f"invalid read address=0x{va:08X} base=0x{base:08X} len={size}")
    return blob[offset:offset+size]


def guarded(path: Path, name: str, size: int, sha: str) -> bytes:
    if not path.is_file():
        abort(f"missing {name}: {path}")
    b=path.read_bytes()
    got=hashlib.sha256(b).hexdigest()
    if len(b)!=size or got!=sha:
        abort(f"canonical {name} image guard failed size=0x{len(b):X} sha={got}")
    return b


def classify_literal_arm_veneer(opcode: int, address: int, read_word) -> dict:
    """Only recognize EXACT LDR PC,[PC,#-4] and LDR PC,[PC,#0].

    ARM PC-relative base at address+8; do not generalize arbitrary LDR or BX.
    Literal may be unmapped: the caller must validate address and image.
    """
    if opcode == 0xE51FF004:  # LDR PC, [PC, #-4]
        literal_va=address+4
    elif opcode == 0xE59FF000:  # LDR PC, [PC]
        literal_va=address+8
    else:
        return {"kind":"NOT_SIMPLE_LITERAL_VENEER","opcode":opcode}
    value=read_word(literal_va)
    return {"kind":"EXACT_ARM_PC_LITERAL_VENEER", "opcode":opcode,
            "literal_va":literal_va,"literal_value":value,
            "target":value & ~1,"target_mode":"THUMB" if value & 1 else "ARM"}


def map_image(va: int, blobs: tuple[tuple[str,bytes,int], ...]):
    for name, blob, base in blobs:
        if base<=va<base+len(blob):
            return name,blob,base
    return None


def self_test():
    memory={0x1004:0xF0317A95, 0x1008:0x10203040}
    neg=classify_literal_arm_veneer(0xE51FF004,0x1000,memory.__getitem__)
    assert neg["kind"]=="EXACT_ARM_PC_LITERAL_VENEER"
    assert (neg["literal_va"],neg["target"],neg["target_mode"])==(0x1004,0xF0317A94,"THUMB")
    pos=classify_literal_arm_veneer(0xE59FF000,0x1000,memory.__getitem__)
    assert (pos["literal_va"],pos["target_mode"])==(0x1008,"ARM")
    unknown=classify_literal_arm_veneer(0xE12FFF1E,0x1000,memory.__getitem__)
    assert unknown["kind"]=="NOT_SIMPLE_LITERAL_VENEER"
    sample=(("ALICE",b"\x00\x01\x02\x03",0x1000),)
    assert map_image(0x1002,sample)[0]=="ALICE"
    assert map_image(0x1004,sample) is None
    assert img_read(b"abcd",0x1000,0x1001,2)==b"bc"
    try:
        img_read(b"abcd",0x1000,0x1003,2)
    except RuntimeError:
        pass
    else:
        abort("self-test out of bounds not enforced")
    assert CALLSITE==SELECT_STORE+2 and ARM_ENTRY&3==0
    print("A120_SELF_TEST=PASS_ARM_LITERAL_VENEER_AND_IMAGE_BOUNDS")


def decode_one(cs, blob:bytes, base:int, va:int, size:int=4):
    insns=list(cs.disasm(img_read(blob,base,va,size),va,count=1))
    if not insns or insns[0].address!=va:
        abort(f"Capstone could not decode at 0x{va:08X}")
    return insns[0]


def disasm_range(cs, blob, base, start, end, max_instructions):
    raw=img_read(blob,base,start,end-start)
    rows=[]
    expected=start
    for ins in cs.disasm(raw,start):
        if ins.address != expected or len(rows)>=max_instructions:
            break
        rows.append(f"  0x{ins.address:08X} {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}")
        expected+=ins.size
        if expected>=end:
            break
    return rows


def analyze(alice:bytes, zimage:bytes):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    except ImportError as ex:
        abort("Capstone not installed: "+str(ex))
    cs_t=Cs(CS_ARCH_ARM, CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs_a=Cs(CS_ARCH_ARM, CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    imgs=(("ALICE",alice,ALICE_BASE),("ZIMAGE",zimage,ZIMAGE_BASE))
    lines=[
       "S13.5A.120 — POST-SELECTION BLX VENEER AND FIRST TARGET CLASSIFICATION",
       "OFFLINE_READ_ONLY=YES NO_PHONE_USB_COM_FLASH_PATCH_REPACK_EMULATOR_EDIT=YES",
       f"ALICE_GUARD=PASS SIZE=0x{len(alice):X} SHA256={ALICE_SHA}",
       f"ZIMAGE_GUARD=PASS SIZE=0x{len(zimage):X} SHA256={ZIMAGE_SHA}",
       "REUSED_A119_CPU_CONTROL=87ED INDEX1 R0=87ED R1=2; VIRTUAL_AUDIO_8928 INDEX2 R0=8928 R1=4",
       "REUSED_A119_CPU_STOP_BEFORE=0x10342FDE (BLX; not real OK or app launch)",
       "LIMIT=EXACT_LOCAL_CODE+ARM_INTERWORK_VENEER+ONE_BOUNDED_TARGET_PREFIX;NOT_FULL_CFG_OR_CALL_CHAIN",
       "", "=== A. ALICE CALLBACK TAIL (LINEAR DISASSEMBLY, NOT CFG) ===",
    ]
    lines+=disasm_range(cs_t,alice,ALICE_BASE,SELECT_CB,CALLSITE+4,50)
    edge=decode_one(cs_t,alice,ALICE_BASE,CALLSITE)
    if edge.mnemonic!="blx":
        abort(f"post-selection callsite drift {edge.mnemonic} {edge.op_str}")
    try:
        decoded_target=int(edge.op_str.strip().lstrip("#"),0)&~1
    except ValueError:
        abort("post-selection BLX is not a direct immediate target")
    if decoded_target != ARM_ENTRY:
        abort(f"post-selection BLX target changed: 0x{decoded_target:08X}")
    lines += [
       "", "=== B. SELECTED STORED VALUE AND CALLSIDE ARGUMENT GATE ===",
       f"CALLSITE_GUARD=PASS 0x{CALLSITE:08X} {edge.mnemonic} {edge.op_str}",
       "A119_BOUNDARY_R0_MATCHES_SELECTED_ID_IN_TWO_SAMPLES=YES",
       "A119_BOUNDARY_R1_EQUALS_TWO_TIMES_INDEX_IN_TWO_SAMPLES=YES_OBSERVATIONAL_ONLY",
       "R1_FULL_CONTROL_FLOW_PROVENANCE=UNPROVEN_UNLESS_LOCAL_DATAFLOW_CONFIRMS",
       "A119_INSTRUMENTED_TRACE_WAS_SELECTION_CALLBACK_NOT_UI_OK=YES",
       "", "=== C. EXACT ARM INTERWORKING ENTRY ===",
    ]
    word=struct.unpack("<I", img_read(alice,ALICE_BASE,ARM_ENTRY,4))[0]
    arm=decode_one(cs_a,alice,ALICE_BASE,ARM_ENTRY)
    lines.append(f"ARM_ENTRY=0x{ARM_ENTRY:08X} OPCODE_LE={img_read(alice,ALICE_BASE,ARM_ENTRY,4).hex()} DISASM={arm.mnemonic} {arm.op_str}")
    veneer=classify_literal_arm_veneer(word,ARM_ENTRY,lambda va:struct.unpack("<I",img_read(alice,ALICE_BASE,va,4))[0])
    lines.append("ARM_ENTRY_TYPE="+veneer["kind"])
    if veneer["kind"]!="EXACT_ARM_PC_LITERAL_VENEER":
        lines+=["ARM_PREFIX_CLASSIFICATION_ONLY=YES"]
        lines+=disasm_range(cs_a,alice,ALICE_BASE,ARM_ENTRY,ARM_ENTRY+min(0x50,ALICE_BASE+len(alice)-ARM_ENTRY),12)
        lines+=["TARGET_RESOLVED=NO_NOT_A_KNOWN_LITERAL_VENEER", "NEXT=DO_NOT_EXECUTE_UNKNOWN_NATIVE_CALLEE"]
    else:
        tgt=veneer["target"]
        lines.append(f"ARM_LITERAL_AT=0x{veneer['literal_va']:08X} RAW_POINTER=0x{veneer['literal_value']:08X}")
        lines.append(f"EFFECTIVE_TARGET=0x{tgt:08X} MODE={veneer['target_mode']}")
        found=map_image(tgt,imgs)
        if found is None:
            lines.append("TARGET_IMAGE=UNMAPPED_NO_FURTHER_DISASSEMBLY")
        else:
            name,blob,base=found
            lines.append(f"TARGET_IMAGE={name} RANGE=[0x{base:08X},0x{base+len(blob):08X})")
            mode=veneer["target_mode"]
            if mode=="ARM" and (tgt&3):
                lines.append("TARGET_ALIGNMENT=INVALID_ARM_NO_DISASSEMBLY")
            elif mode=="THUMB" and (tgt&1):
                lines.append("TARGET_ALIGNMENT=INVALID_THUMB_NO_DISASSEMBLY")
            else:
                lines.append("=== D. RESOLVED TARGET FIRST BASIC-BLOCK PREFIX (NO EXECUTION) ===")
                cs=cs_t if mode=="THUMB" else cs_a
                data=img_read(blob,base,tgt,min(240,base+len(blob)-tgt))
                expected=tgt
                transfers=[]
                count=0
                for ins in cs.disasm(data,tgt):
                    if count>=PREFIX_MAX_INSTRUCTIONS or ins.address!=expected:
                        break
                    lines.append(f"  0x{ins.address:08X} {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}")
                    count+=1
                    expected+=ins.size
                    if (ins.mnemonic in {"bl","blx","bx","b","b.w","pop","svc","swi"}
                            or ins.mnemonic.startswith("b") and ins.mnemonic not in {"bic","bics","bkpt"}):
                        transfers.append((ins.address,ins.mnemonic,ins.op_str))
                        # Do not fake full reachable CFG by decoding past a transfer.
                        break
                lines.append(f"TARGET_PREFIX_DECODED_INSTRUCTIONS={count}")
                if transfers:
                    x=transfers[0]
                    lines.append(f"FIRST_TARGET_CONTROL_TRANSFER=0x{x[0]:08X} {x[1]} {x[2]}")
                else:
                    lines.append("FIRST_TARGET_CONTROL_TRANSFER=NOT_FOUND_IN_LIMITED_PREFIX")
    lines += [
      "", "=== DECISION ===",
      "STRUCTURAL_TARGET_CLASSIFICATION="+("VENEER_RESOLVED" if veneer["kind"]=="EXACT_ARM_PC_LITERAL_VENEER" else "ARM_ENTRY_NOT_SIMPLE_VENEER"),
      "NEXT_EDGE_OR_APP_ACTION_SEMANTICS=UNPROVEN",
      "SELECTED_MENU_INDEX_TO_ID_CPU=PASS_CONDITIONAL_A118_A119",
      "REAL_UI_OK_EVENT=NOT_TRACED",
      "NATIVE_AUDIO_APPLICATION_OPEN_PLAY=NOT_PROVEN",
      "REAL_B702_STORAGE_RELOCATION_AND_BOOT_INTEGRITY=NOT_PROVEN",
      "NO_BINARY_EDIT_OR_EMULATED_NATIVE_AUDIO_CALLBACK=YES",
    ]
    return "\n".join(lines)+"\n"


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,default=Path(r"C:\Users\verto\F2-Altice-MobiWire"))
    p.add_argument("--out",type=Path)
    p.add_argument("--self-test",action="store_true")
    args=p.parse_args()
    self_test()
    if args.self_test:
        return
    root=args.root
    alice=guarded(root/"research/f2/work/extracted/altice_alice/alice-py.bin","ALICE",ALICE_SIZE,ALICE_SHA)
    zimage=guarded(root/"research/f2/work/extracted/altice_platform/zimage.bin","ZIMAGE",ZIMAGE_SIZE,ZIMAGE_SHA)
    report=analyze(alice,zimage)
    out=args.out or root/"research/f2/work/reports"/REPORT
    if not out.parent.is_dir():
        abort(f"missing report parent {out.parent}")
    with out.open("x",encoding="utf-8",newline="\n") as f:
        f.write(report)
    print(f"A120_REPORT_CREATED={out} BYTES={out.stat().st_size}")
    print("A120_STATIC_RESULT=BOUNDARY_AND_TARGET_CLASSIFIED_NO_UI_LAUNCH_PROOF")

if __name__=="__main__":
    try:
        main()
    except Exception as ex:
        print(f"A120_FAILED={type(ex).__name__}: {ex}",file=sys.stderr)
        sys.exit(2)
