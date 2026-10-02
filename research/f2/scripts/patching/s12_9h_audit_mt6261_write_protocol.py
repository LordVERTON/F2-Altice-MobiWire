#!/usr/bin/env python3

from pathlib import Path
import re


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

OUT = (
    ROOT
    / "research"
    / "f2"
    / "work"
    / "repro"
)

DONOR = (
    MTK
    / "research"
    / "f2"
    / "work"
    / "donor_repos"
    / "MT2503-2"
)

REPORT = (
    OUT
    / "s12_9h_mt6261_write_protocol_audit.txt"
)


def text(path):
    try:
        return path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        return ""


def print_window(path, start, end):
    src = text(path).splitlines()

    print()
    print("=" * 116)
    print(
        f"{path} :: {start}-{end}"
    )
    print("=" * 116)

    for n in range(
        max(1, start),
        min(len(src), end) + 1,
    ):
        print(
            f"{n:5d}: {src[n-1]}"
        )


def grep_tree(root, patterns):
    rx = re.compile(
        "|".join(
            f"(?:{x})"
            for x in patterns
        ),
        re.I,
    )

    hits = []

    if not root.exists():
        return hits

    for path in root.rglob("*"):

        if not path.is_file():
            continue

        # Source / map / config files only.
        if path.suffix.lower() not in {
            ".c", ".h", ".cpp", ".inc",
            ".py", ".txt", ".cfg",
            ".map", ".lis", ".log",
            ".mak", ".mk", ".def",
            ".s", ".asm",
        }:
            continue

        src = text(path)

        if not src:
            continue

        for lineno, line in enumerate(
            src.splitlines(),
            1,
        ):
            if rx.search(line):

                hits.append(
                    (
                        path,
                        lineno,
                        line.rstrip(),
                    )
                )

    return hits


def function_body(path, function_name):
    src = text(path).splitlines()

    pattern = re.compile(
        rf"^\s*def\s+{re.escape(function_name)}\s*\("
    )

    start = None
    indent = None

    for i, line in enumerate(src):

        if pattern.search(line):

            start = i
            indent = (
                len(line)
                - len(line.lstrip())
            )

            break

    if start is None:
        return []

    end = len(src)

    for i in range(
        start + 1,
        len(src),
    ):
        line = src[i]

        if not line.strip():
            continue

        current = (
            len(line)
            - len(line.lstrip())
        )

        if (
            current <= indent
            and re.match(
                r"^\s*(def|class)\s+",
                line,
            )
        ):
            end = i
            break

    return [
        (
            i + 1,
            src[i],
        )
        for i in range(
            start,
            end,
        )
    ]


LEGACY = (
    MTK
    / "mtkclient"
    / "Library"
    / "DA"
    / "legacy"
    / "dalegacy_lib.py"
)

PARAM = (
    MTK
    / "mtkclient"
    / "Library"
    / "DA"
    / "legacy"
    / "dalegacy_param.py"
)


lines = []


def log(s=""):
    print(s)
    lines.append(s)


log("=" * 116)
log("S12.9H - MT6261 / SERIAL-FLASH WRITE PROTOCOL AUDIT")
log("=" * 116)
log()
log("NO DEVICE ACCESS")
log("NO BROM")
log("NO WRITE")
log("NO ERASE")


# ------------------------------------------------------------------
# A. Command constants
# ------------------------------------------------------------------

log()
log("=" * 116)
log("A. MTKCLIENT LEGACY COMMAND CONSTANTS")
log("=" * 116)


param_src = text(PARAM).splitlines()

wanted = (
    "SDMMC_WRITE_DATA_CMD",
    "SDMMC_WRITE_IMAGE_CMD",
    "SF_WRITE_IMAGE_CMD",
    "NOR_WRITE_DATA_CMD",
    "NOR_WRITE_PTB_CMD",
    "FORMAT_CMD",
    "READ_CMD",
)

for lineno, line in enumerate(
    param_src,
    1,
):

    if any(
        x in line
        for x in wanted
    ):
        log(
            f"{lineno:5d}: {line}"
        )


# ------------------------------------------------------------------
# B. Exact Python write/read framing
# ------------------------------------------------------------------

log()
log("=" * 116)
log("B. EXACT LEGACY PYTHON PROTOCOL FRAMING")
log("=" * 116)


for fn in (
    "sdmmc_write_data",
    "writeflash",
    "formatflash",
    "readflash",
):

    body = function_body(
        LEGACY,
        fn,
    )

    log()
    log(
        f"--- {fn} ---"
    )

    for lineno, line in body:

        if (
            fn in ("sdmmc_write_data", "writeflash", "formatflash")
            or
            any(
                x in line
                for x in (
                    "flashtype",
                    "config.iot",
                    "pack(",
                    "READ_CMD",
                    "packetsize",
                    "hwcode",
                )
            )
        ):

            log(
                f"{lineno:5d}: {line}"
            )


# ------------------------------------------------------------------
# C. Automatic framing classification
# ------------------------------------------------------------------

write_body = "\n".join(
    line
    for _, line
    in function_body(
        LEGACY,
        "sdmmc_write_data",
    )
)

read_body = "\n".join(
    line
    for _, line
    in function_body(
        LEGACY,
        "readflash",
    )
)


write_iot_branch = (
    "config.iot"
    in write_body
)

write_q_addr = bool(
    re.search(
        r'pack\(\s*[\'"]>Q[\'"]\s*,\s*addr',
        write_body,
    )
)

write_q_length = bool(
    re.search(
        r'pack\(\s*[\'"]>Q[\'"]\s*,\s*length',
        write_body,
    )
)

read_has_iot = (
    "config.iot"
    in read_body
)

read_i_addr = bool(
    re.search(
        r'pack\(\s*[\'"]>I[\'"]\s*,\s*addr',
        read_body,
    )
)

read_i_length = bool(
    re.search(
        r'pack\(\s*[\'"]>I[\'"]\s*,\s*length',
        read_body,
    )
)


log()
log("=" * 116)
log("C. FRAMING CLASSIFICATION")
log("=" * 116)

log(
    f"write path has config.iot branch : "
    f"{write_iot_branch}"
)

log(
    f"write addr uses >Q              : "
    f"{write_q_addr}"
)

log(
    f"write length uses >Q            : "
    f"{write_q_length}"
)

log(
    f"read path has config.iot branch : "
    f"{read_has_iot}"
)

log(
    f"read IoT addr has >I framing    : "
    f"{read_i_addr}"
)

log(
    f"read IoT length has >I framing  : "
    f"{read_i_length}"
)


if (
    not write_iot_branch
    and write_q_addr
    and write_q_length
    and read_has_iot
    and read_i_addr
    and read_i_length
):

    log()
    log(
        "RESULT: GENERIC WRITE FRAMING != NOR IOT READ FRAMING"
    )

    log(
        "Do NOT assume DALegacy.writeflash() is MT6261-safe."
    )


# ------------------------------------------------------------------
# D. All references to legacy SF/NOR write commands in mtkclient
# ------------------------------------------------------------------

log()
log("=" * 116)
log("D. MTKCLIENT REFERENCES TO SF/NOR WRITE COMMANDS")
log("=" * 116)


mtk_hits = grep_tree(
    MTK / "mtkclient",
    [
        r"SF_WRITE_IMAGE_CMD",
        r"NOR_WRITE_DATA_CMD",
        r"NOR_WRITE_PTB_CMD",
        r"SDMMC_WRITE_DATA_CMD",
        r"MTK_DA_STORAGE_NOR",
    ],
)


for path, lineno, line in mtk_hits:

    log(
        f"{path.relative_to(MTK)}:"
        f"{lineno}: {line}"
    )


# ------------------------------------------------------------------
# E. Search MT2503/MT6261 donor source
# ------------------------------------------------------------------

log()
log("=" * 116)
log("E. DONOR MT2503 / MT6261 WRITE + ERASE SYMBOL SEARCH")
log("=" * 116)


donor_patterns = [
    r"SF_WRITE_IMAGE",
    r"NOR_WRITE_DATA",
    r"NOR_WRITE_PTB",
    r"SDMMC_WRITE_DATA",
    r"WRITE_IMAGE_CMD",
    r"WRITE_DATA_CMD",

    r"SF_DAL.*Erase",
    r"SF_DAL.*Program",
    r"SF_DAL.*Write",
    r"SF_DAL.*Block",
    r"SF_DAL.*Sector",

    r"EraseBlock",
    r"EraseSector",
    r"BlockErase",
    r"SectorErase",
    r"PageProgram",
    r"Page_Program",
    r"ProgramPage",

    r"flash_mtd_sf",
    r"combo_flash_nor",

    r"0x20.*erase",
    r"0xD8.*erase",
    r"erase.*0x20",
    r"erase.*0xD8",
]


donor_hits = grep_tree(
    DONOR,
    donor_patterns,
)


log(
    f"hit count = {len(donor_hits)}"
)

for path, lineno, line in donor_hits[:3000]:

    try:
        rel = path.relative_to(DONOR)
    except Exception:
        rel = path

    log(
        f"{rel}:{lineno}: {line}"
    )


# ------------------------------------------------------------------
# F. Focused contexts around likely SF DAL implementations
# ------------------------------------------------------------------

log()
log("=" * 116)
log("F. FOCUSED SF-DAL SOURCE CONTEXTS")
log("=" * 116)


focus_files = []

if DONOR.exists():

    for p in DONOR.rglob("*"):

        if not p.is_file():
            continue

        low = p.name.lower()

        if (
            "flash_mtd_sf" in low
            or "combo_flash_nor" in low
        ):
            focus_files.append(p)


for p in sorted(
    set(focus_files)
):

    src = text(p).splitlines()

    log()
    log(
        f"### {p.relative_to(DONOR)}"
    )

    for idx, line in enumerate(src):

        if re.search(
            r"erase|program|write|block|sector",
            line,
            re.I,
        ):

            lo = max(
                0,
                idx - 3,
            )

            hi = min(
                len(src),
                idx + 4,
            )

            log()

            for n in range(
                lo,
                hi,
            ):
                log(
                    f"{n+1:6d}: "
                    f"{src[n]}"
                )


# ------------------------------------------------------------------
# G. Conservative final classification
# ------------------------------------------------------------------

log()
log("=" * 116)
log("S12.9H CLASSIFICATION")
log("=" * 116)

log(
    "FACT: exact F2 loader capacity descriptor = 4 MiB."
)

log(
    "FACT: exact F2 loader fixed block field = 0x1000."
)

log(
    "STRONGLY SUPPORTED: 0x1000 represents SF erase/block granularity."
)

log(
    "FACT: mtkclient NOR-IoT read path uses special IoT framing."
)

log(
    "FACT: generic sdmmc_write_data path has no IoT-specific framing branch."
)

log(
    "UNKNOWN: actual MT6261 service-loader write command and framing."
)

log(
    "UNKNOWN: whether SF write performs erase-before-program."
)

log(
    "FLASH AUTHORIZED: NO"
)


REPORT.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)

print()
print(
    "Report:",
    REPORT,
)
