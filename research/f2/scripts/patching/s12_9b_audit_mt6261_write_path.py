#!/usr/bin/env python3

from pathlib import Path
import hashlib
import re

MTK = Path(r"C:\Users\verto\mtkclient")

OUT = (
    Path(r"C:\Users\verto\F2-Altice-MobiWire")
    / "research" / "f2" / "work" / "repro"
)

REPORT = OUT / "s12_9b_mt6261_write_path_audit.txt"

OUT.mkdir(
    parents=True,
    exist_ok=True,
)


def sha256(path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            b = f.read(1024 * 1024)

            if not b:
                break

            h.update(b)

    return h.hexdigest()


def read_lines(rel):
    path = MTK / rel

    if not path.is_file():
        return path, []

    return path, path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()


def emit_window(lines_out, rel, start, end):
    path, lines = read_lines(rel)

    lines_out.append("")
    lines_out.append("=" * 118)
    lines_out.append(
        f"{rel} :: lines {start}-{end}"
    )
    lines_out.append("=" * 118)

    if not lines:
        lines_out.append("FILE MISSING")
        return

    lo = max(1, start)
    hi = min(len(lines), end)

    for n in range(lo, hi + 1):
        lines_out.append(
            f"{n:5d}: {lines[n-1]}"
        )


def grep_repo(patterns):
    rx = re.compile(
        "|".join(
            f"(?:{p})"
            for p in patterns
        ),
        re.I,
    )

    hits = []

    root = MTK / "mtkclient"

    for path in root.rglob("*.py"):

        try:
            lines = path.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()

        except Exception:
            continue

        for lineno, line in enumerate(
            lines,
            1,
        ):
            if rx.search(line):
                hits.append(
                    (
                        str(
                            path.relative_to(MTK)
                        ),
                        lineno,
                        line.rstrip(),
                    )
                )

    return hits


out = []

out.append("=" * 118)
out.append(
    "S12.9B - STATIC MT6261 / IOT WRITE-PATH AUDIT"
)
out.append("=" * 118)

out.append("")
out.append("NO DEVICE ACCESS")
out.append("NO BROM SESSION")
out.append("NO WRITE")
out.append("NO ERASE")


# ------------------------------------------------------------------
# Commit
# ------------------------------------------------------------------

git_head = (
    MTK / ".git"
)

out.append("")
out.append("LOCAL TREE")
out.append("-" * 118)

try:
    import subprocess

    head = subprocess.check_output(
        [
            "git",
            "-C",
            str(MTK),
            "rev-parse",
            "HEAD",
        ],
        text=True,
    ).strip()

    out.append(
        f"git HEAD = {head}"
    )

except Exception as e:
    out.append(
        f"git HEAD unavailable: {e!r}"
    )


# ------------------------------------------------------------------
# Exact source windows
# ------------------------------------------------------------------

windows = [
    (
        "mtkclient/config/brom_config.py",
        770,
        810,
    ),

    (
        "mtkclient/config/mtk_config.py",
        155,
        185,
    ),

    (
        "mtkclient/Library/mtk_preloader.py",
        160,
        290,
    ),

    (
        "mtkclient/Library/mtk_preloader.py",
        325,
        380,
    ),

    (
        "mtkclient/Library/mtk_preloader.py",
        400,
        470,
    ),

    (
        "mtkclient/Library/mtk_preloader.py",
        520,
        560,
    ),

    (
        "mtkclient/Library/DA/daconfig.py",
        195,
        235,
    ),

    (
        "mtkclient/Library/DA/mtk_daloader.py",
        55,
        95,
    ),

    (
        "mtkclient/Library/DA/mtk_daloader.py",
        190,
        225,
    ),

    (
        "mtkclient/Library/DA/mtk_daloader.py",
        310,
        345,
    ),

    (
        "mtkclient/Library/DA/mtk_da_handler.py",
        100,
        135,
    ),

    (
        "mtkclient/Library/DA/mtk_da_handler.py",
        150,
        180,
    ),

    (
        "mtkclient/Library/DA/legacy/dalegacy_lib.py",
        530,
        700,
    ),

    (
        "mtkclient/Library/DA/legacy/dalegacy_lib.py",
        800,
        860,
    ),

    (
        "mtkclient/Library/DA/legacy/dalegacy_lib.py",
        1060,
        1210,
    ),

    (
        "mtkclient/Library/DA/legacy/extension/legacy.py",
        290,
        330,
    ),
]

for rel, start, end in windows:
    emit_window(
        out,
        rel,
        start,
        end,
    )


# ------------------------------------------------------------------
# Payload census
# ------------------------------------------------------------------

out.append("")
out.append("=" * 118)
out.append("MT6261 PAYLOAD / LOADER FILES")
out.append("=" * 118)

payloads = []

for p in MTK.rglob("*6261*"):

    if not p.is_file():
        continue

    payloads.append(p)

if not payloads:
    out.append(
        "No filename containing 6261 found."
    )

for p in sorted(payloads):

    try:
        size = p.stat().st_size
        digest = sha256(p)

    except Exception as e:
        out.append(
            f"{p}: ERROR {e!r}"
        )
        continue

    out.append(
        f"{p}"
    )

    out.append(
        f"  size   = 0x{size:X} ({size})"
    )

    out.append(
        f"  SHA256 = {digest}"
    )


# ------------------------------------------------------------------
# Focused searches
# ------------------------------------------------------------------

search_sets = {
    "MT6261 + IOT FLOW": [
        r"0x6261",
        r"MT6261",
        r"config\.iot",
        r"chipconfig\.iot",
        r"dump_internal_flash",
    ],

    "NOR FLASH OPERATIONS": [
        r"NOR_",
        r"\bnor\b",
        r"writeflash",
        r"eraseflash",
        r"erase_flash",
        r"formatflash",
        r"format_flash",
    ],

    "FLASH GEOMETRY": [
        r"erase_size",
        r"block_size",
        r"sector_size",
        r"pagesize",
        r"flashsize",
        r"flash_size",
        r"nor.*size",
    ],

    "LEGACY DA COMMANDS": [
        r"WRITE_DATA",
        r"WRITE_IMAGE",
        r"FORMAT",
        r"ERASE",
        r"NOR",
    ],

    "IOT WRITE GUARDS": [
        r"if .*iot",
        r"if not .*iot",
        r"iot.*write",
        r"write.*iot",
        r"iot.*erase",
        r"erase.*iot",
    ],
}

for title, patterns in search_sets.items():

    out.append("")
    out.append("=" * 118)
    out.append(title)
    out.append("=" * 118)

    hits = grep_repo(patterns)

    for rel, lineno, line in hits:

        # Keep the report manageable.
        if len(out) > 20000:
            break

        out.append(
            f"{rel}:{lineno}: {line}"
        )


# ------------------------------------------------------------------
# Direct writeflash context detection
# ------------------------------------------------------------------

out.append("")
out.append("=" * 118)
out.append("DALEGACY WRITEFLASH STRUCTURAL CHECK")
out.append("=" * 118)

rel = (
    "mtkclient/Library/DA/"
    "legacy/dalegacy_lib.py"
)

path, lines = read_lines(rel)

if lines:

    def_idx = None

    for i, line in enumerate(lines):

        if re.search(
            r"^\s*def\s+writeflash\s*\(",
            line,
        ):
            def_idx = i
            break

    if def_idx is None:
        out.append(
            "writeflash() not found"
        )

    else:

        end = min(
            len(lines),
            def_idx + 180,
        )

        block = lines[
            def_idx:end
        ]

        out.append(
            f"writeflash definition line "
            f"{def_idx+1}"
        )

        checks = [
            "self.config.iot",
            "hwcode",
            "0x6261",
            "NOR",
            "erase",
            "format",
            "WRITE",
        ]

        for word in checks:

            matches = [
                (
                    def_idx
                    + n
                    + 1,
                    line,
                )
                for n, line
                in enumerate(block)
                if word.lower()
                in line.lower()
            ]

            out.append("")
            out.append(
                f"[{word}] "
                f"{len(matches)} hit(s)"
            )

            for lineno, line in matches:
                out.append(
                    f"  {lineno}: "
                    f"{line.rstrip()}"
                )


# ------------------------------------------------------------------
# Final classification - deliberately conservative
# ------------------------------------------------------------------

out.append("")
out.append("=" * 118)
out.append("S12.9B PRELIMINARY CLASSIFICATION")
out.append("=" * 118)

out.append(
    "FACT: MT6261 / 0x6261 has explicit IoT handling "
    "in the local source tree."
)

out.append(
    "FACT: MT6261 has an explicit internal-flash "
    "read path."
)

out.append(
    "FACT: generic DA layers expose writeflash / "
    "erase-related code."
)

out.append(
    "UNKNOWN: whether the MT6261 IoT execution path "
    "actually reaches a NOR-safe write primitive."
)

out.append(
    "UNKNOWN: actual erase granularity of this F2 NOR."
)

out.append(
    "UNKNOWN: whether mt6261_payload.bin contains "
    "a usable flash-program/erase implementation."
)

out.append(
    "FLASH AUTHORIZED: NO"
)

out.append("")
out.append(
    "NEXT DECISION REQUIRES MANUAL REVIEW OF THIS REPORT."
)


REPORT.write_text(
    "\n".join(out) + "\n",
    encoding="utf-8",
)

print(
    "\n".join(out)
)

print()
print(
    "Report:",
    REPORT,
)
