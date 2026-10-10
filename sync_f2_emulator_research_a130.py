#!/usr/bin/env python3
"""Synchronize evidence-only A130 research notes to a separate emulator worktree.
No emulator source, ROM, or tests are modified. Refuses unsafe branch/path or overwrite.
"""
import argparse, pathlib, subprocess, sys

CONTENT = '''# F2 Altice/MobiWire — Research sync (S13.5A.130)

**As of 2026-10-10. Evidence notes only. Does not activate Audio or modify emulator behavior.**

## Three distinct layers

1. **Observed device UI:** Multimedia = `1 Image viewer`, `2 FM radio`; `Extras > Services` = `Empty`. A manual advertises Audio/Video but not necessarily in this firmware build.
2. **ROM-supported facts:** B702 currently enumerates two child IDs `[0x8569, 0x87ED]`; `0x87ED` is linked with Image Viewer. FM ROM numeric ID remains **unknown**; **never** equate `0x8569` to FM without ROM proof. Native Audio ID `0x8928` exists but is absent from the B702 children list. The B702-to-observed-Multimedia correspondence is not yet fully proven.
3. **Optional synthetic overlay:** `[0x8569, 0x87ED, 0x8928]` for CPU harness tests only. A117–119 Unicorn tests show index 2 can reach `0x8928` in `descriptor+0x18` under synthetic descriptors and mocked external functions. This is **not** proof of real UI OK press, launch, playback, or ROM patch viability.

## Canonical segment guards

- ALICE: `base=0x1024EC00`, `size=0x157BB4`, SHA-256 `7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea`.
- BOOT_ZIMAGE: `base=0xF01F19E4`, `size=0x4B06C`, SHA-256 `aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e`.
- ZIMAGE: `base=0xF023CA50`, `size=0x185E98`, SHA-256 `85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954`.

## Recent evidence (reports in main project, not emulator)

- A120–124: Selected-row callback continuation crosses a BOOT veneer into task/state handling; four later veneer targets are outside these three image mappings. **Close this generic BOOT task detour** absent new memory-map evidence.
- A125: `0x10336788` calls native resolver `0x1034C7E4` then performs an indirect callback `BLX r4`; no verified connection to actual OK key. Audio registration stub `0x1033D841`, init `0x1033E815`, follow-up `0x1033F83C` exist, but stub ≠ proven launcher.
- A126–129: `0x10345268` reads selected ID at descriptor `+0x18`, maps ID→index via `0x10319DF8`, calls UI message constructor `0x102EF44C`, then conditionally `0x10387D94`. Follow-up updates parent/history/depth and calls `0x10347432 → 0x10340ADC`. The UI transport `0x102FC624` ARM veneer resolves to Thumb `0xF02B61FC` in ZIMAGE.
- **A130 PASS:** `0xF02B61FC` = 4-instruction wrapper setting `r2=1`, then calling `0xF0312408`; not yet an OK-key event consumer. `0x10340ADC` = 242-instruction menu refresh CFG. It populates `descriptor+0x40` (child-list pointer), reads `descriptor+0x48` (child count), loops `0x10315514` index→ID and `0x103452B8` per-item predicate, and sends UI message through `0x102FC624`. This is a rendering/list consumption path **not a proven leaf-app launch**.
- **A131 prepared, result not available at this sync:** targeted inspection of `0x103452B8`, `0x10343050`, `0x103431BC`; do not assert PASS or inferred semantics.

## Emulator invariant / promotion gates

- Keep observed UI, ROM-proven registry, and experimental overlay strictly separate. Preserve existing V5.1 tests, overlay opt-in, two real Multimedia entries, nine B709 slots, and FM ID null unless independently proven.
- No in-place append to B702: adjacent ROM record collision. Future patch needs a validated relocation address, all pointer references, loader/repack and integrity checks.
- Positive control: prove actual Image Viewer (`0x87ED`) leaf activation; then establish Audio (`0x8928`) launch and MP3 playback independently.
- No hardware flash or source-ROM modification. Canonical dumps, NVRAM, IMEI, calibration and user FS are immutable.

**Source of truth:** `LordVERTON/F2-Altice-MobiWire` main audit scripts/reports and Notion AI Handoff. This page is a dated evidence snapshot; it must not silently change the emulator's observed UI or native ROM model.
'''

def main():
    p=argparse.ArgumentParser();p.add_argument('--emulator',type=pathlib.Path,required=True);a=p.parse_args()
    root=a.emulator.resolve(strict=True)
    if not (root/'.git').exists():raise RuntimeError('ABORT_NOT_GIT_WORKTREE_ROOT')
    branch=subprocess.check_output(['git','-C',str(root),'branch','--show-current'],text=True).strip()
    if branch!='feature/f2-virtual-menu-lab':raise RuntimeError('ABORT_WRONG_BRANCH='+branch)
    status=subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True).strip()
    if status:raise RuntimeError('ABORT_DIRTY_WORKTREE (commit/stash unrelated changes first)')
    path=root/'docs'/'f2_research_sync_a130.md'
    if path.exists():raise RuntimeError('ABORT_REFUSE_OVERWRITE='+str(path))
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8',newline='\n') as f:f.write(CONTENT)
    print('SYNC_RESULT=PASS_DOCS_ONLY');print('OUTPUT='+str(path));print('BRANCH='+branch)
    print('NEXT=Review then git add docs/f2_research_sync_a130.md && git commit -m "docs(emulator): sync F2 A130 research evidence"')
    return 0
if __name__=='__main__':
    try:sys.exit(main())
    except Exception as e:print(str(e),file=sys.stderr);sys.exit(1)
