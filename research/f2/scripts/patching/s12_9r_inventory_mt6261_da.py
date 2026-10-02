#!/usr/bin/env python3

from pathlib import Path
import hashlib
import json
import struct


HOME = Path(r"C:\Users\verto")
MTK = HOME / "mtkclient"
ROOT = HOME / "F2-Altice-MobiWire"

REPRO = ROOT / "research" / "f2" / "work" / "repro"

REPORT = REPRO / "s12_9r_mt6261_da_inventory.txt"
MANIFEST = REPRO / "s12_9r_mt6261_da_inventory.json"

LIVE = REPRO / "s12_8_serial_readback_A.bin"
CAND = REPRO / "s12_8e_live_preserving_candidate_NOT_FOR_FLASH.bin"

SACRIFICIAL = 0x2A0000
LIVE_TAIL = 0x2C0000

SEARCH_ROOTS = [
    MTK,
    ROOT,

    HOME / "Arduino_IDE_for_RePhone",
    HOME / "Downloads" / "Arduino_IDE_for_RePhone",
    HOME / "Desktop" / "Arduino_IDE_for_RePhone",
    HOME / "Documents" / "Arduino_IDE_for_RePhone",
]

SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    ".idea",
    ".vscode",
}

BINARY_SUFFIXES = {
    "",
    ".bin",
    ".da",
    ".dat",
    ".img",
    ".rom",
    ".payload",
}

MAX_FILE = 64 * 1024 * 1024

TARGET_HW = {
    0x6261: "MT6261",
    0x6260: "MT6260",
    0x2502: "MT2502",
    0x2503: "MT2503",
    0x2523: "MT2523",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


lines = []


def log(s=""):
    print(s)
    lines.append(s)


def is_binary_candidate(path):
    try:
        size = path.stat().st_size
    except OSError:
        return False

    if size < 0x40 or size > MAX_FILE:
        return False

    if path.suffix.lower() not in BINARY_SUFFIXES:
        return False

    return True


def walk(root):
    if not root.exists():
        return

    stack = [root]

    while stack:

        cur = stack.pop()

        try:
            entries = list(cur.iterdir())
        except (OSError, PermissionError):
            continue

        for p in entries:

            if p.is_dir():

                if p.name.lower() in SKIP_DIRS:
                    continue

                stack.append(p)

            elif p.is_file():

                if is_binary_candidate(p):
                    yield p


def parse_dada(data, pos):
    """
    MediaTek All-In-One DA entry candidate.

    Header:
      10 x uint16 little endian

      magic
      hw_code
      hw_sub_code
      hw_version
      sw_version
      reserved1
      pagesize
      reserved3
      entry_region_index
      entry_region_count

    Followed by N region descriptors:

      m_buf
      m_len
      m_start_addr
      m_start_offset
      m_sig_len

    each uint32 little endian.
    """

    if pos + 20 > len(data):
        return None

    vals = struct.unpack_from(
        "<10H",
        data,
        pos,
    )

    (
        magic,
        hw_code,
        hw_sub_code,
        hw_version,
        sw_version,
        reserved1,
        pagesize,
        reserved3,
        entry_region_index,
        entry_region_count,
    ) = vals

    if magic != 0xDADA:
        return None

    if not (1 <= entry_region_count <= 32):
        return None

    regions_off = pos + 20
    need = regions_off + entry_region_count * 20

    if need > len(data):
        return None

    regions = []
    valid_regions = 0

    for i in range(entry_region_count):

        off = regions_off + i * 20

        (
            m_buf,
            m_len,
            m_start_addr,
            m_start_offset,
            m_sig_len,
        ) = struct.unpack_from(
            "<5I",
            data,
            off,
        )

        file_valid = (
            m_len > 0
            and m_buf < len(data)
            and m_buf + m_len <= len(data)
        )

        if file_valid:
            valid_regions += 1

        regions.append({
            "index": i,
            "m_buf": m_buf,
            "m_len": m_len,
            "m_start_addr": m_start_addr,
            "m_start_offset": m_start_offset,
            "m_sig_len": m_sig_len,
            "file_valid": file_valid,
        })

    # Require at least one plausible region.
    if valid_regions == 0:
        return None

    score = 0

    if hw_code == 0x6261:
        score += 1000

    elif hw_code in TARGET_HW:
        score += 400

    if entry_region_count >= 2:
        score += 100

    if (
        entry_region_index < entry_region_count
        and entry_region_index + 1 < entry_region_count
    ):
        score += 200

    score += valid_regions * 10

    return {
        "offset": pos,
        "magic": magic,
        "hw_code": hw_code,
        "hw_name": TARGET_HW.get(
            hw_code,
            "UNKNOWN",
        ),
        "hw_sub_code": hw_sub_code,
        "hw_version": hw_version,
        "sw_version": sw_version,
        "reserved1": reserved1,
        "pagesize": pagesize,
        "reserved3": reserved3,
        "entry_region_index": entry_region_index,
        "entry_region_count": entry_region_count,
        "valid_regions": valid_regions,
        "regions": regions,
        "score": score,
    }


def scan_dada(data):
    out = []

    pos = 0

    while True:

        pos = data.find(
            b"\xDA\xDA",
            pos,
        )

        if pos < 0:
            break

        rec = parse_dada(
            data,
            pos,
        )

        if rec is not None:
            out.append(rec)

        pos += 2

    return out


log("=" * 120)
log("S12.9R - OFFLINE MT6261 DOWNLOAD-AGENT INVENTORY")
log("=" * 120)

log()
log("NO DEVICE ACCESS")
log("NO BROM")
log("NO DA UPLOAD")
log("NO JUMP DA")
log("NO WRITE")
log("NO ERASE")


# --------------------------------------------------------------------
# A. Re-check sacrificial-sector safety at larger erase granularities
# --------------------------------------------------------------------

log()
log("=" * 120)
log("A. SACRIFICIAL ERASE-GRANULARITY ENVELOPE")
log("=" * 120)

if LIVE.is_file() and CAND.is_file():

    live = LIVE.read_bytes()
    cand = CAND.read_bytes()

    assert len(live) == 0x400000
    assert len(cand) == 0x400000

    for gran in (
        0x1000,
        0x10000,
        0x20000,
        0x40000,
    ):

        base = (
            SACRIFICIAL
            // gran
            * gran
        )

        end = base + gran

        lv = live[base:end]
        cv = cand[base:end]

        all_ff = (
            lv == cv
            and lv == b"\xFF" * gran
        )

        below_tail = (
            end <= LIVE_TAIL
        )

        safe = (
            all_ff
            and below_tail
        )

        log(
            f"gran=0x{gran:05X} "
            f"block=0x{base:06X}..0x{end-1:06X} "
            f"all_ff={'YES' if all_ff else 'NO '} "
            f"below_tail={'YES' if below_tail else 'NO '} "
            f"=> {'PASS' if safe else 'FAIL'}"
        )

else:
    log("LIVE/CAND not found: geometry re-check skipped")


# --------------------------------------------------------------------
# B. Explicit known MT6261 payload
# --------------------------------------------------------------------

log()
log("=" * 120)
log("B. KNOWN mt6261_payload.bin")
log("=" * 120)

payload_hits = []

for root in SEARCH_ROOTS:

    if not root.exists():
        continue

    try:
        hits = list(
            root.rglob(
                "mt6261_payload.bin"
            )
        )
    except (OSError, PermissionError):
        hits = []

    for p in hits:

        try:
            data = p.read_bytes()
        except OSError:
            continue

        item = {
            "path": str(p),
            "size": len(data),
            "sha256": sha256(data),
        }

        payload_hits.append(item)

        log(
            f"{p}"
        )

        log(
            f"  size   = 0x{len(data):X}"
        )

        log(
            f"  sha256 = {sha256(data)}"
        )

        if len(data) == 0x250:
            log(
                "  classification = SMALL AUXILIARY PAYLOAD / NOT FULL DA"
            )

        log()


# --------------------------------------------------------------------
# C. Exact RePhone-style Download_Agent paths
# --------------------------------------------------------------------

log()
log("=" * 120)
log("C. DOWNLOAD_AGENT / 6261 PATH CENSUS")
log("=" * 120)

download_agent_files = []

for root in SEARCH_ROOTS:

    if not root.exists():
        continue

    for p in walk(root):

        low = str(p).lower().replace("/", "\\")

        if (
            "download_agent" in low
            or "\\6261\\" in low
            or "mt6261" in p.name.lower()
        ):

            try:
                data = p.read_bytes()
            except OSError:
                continue

            item = {
                "path": str(p),
                "size": len(data),
                "sha256": sha256(data),
            }

            download_agent_files.append(
                item
            )

            log(
                f"{p}"
            )

            log(
                f"  size   = 0x{len(data):X}"
            )

            log(
                f"  sha256 = {sha256(data)}"
            )


if not download_agent_files:
    log("NONE")


# --------------------------------------------------------------------
# D. Scan all plausible local binaries for DADA DA entries
# --------------------------------------------------------------------

log()
log("=" * 120)
log("D. DADA ENTRY SCAN")
log("=" * 120)

files_scanned = 0
dada_files = []
records = []

seen = set()

for root in SEARCH_ROOTS:

    if not root.exists():
        continue

    for p in walk(root):

        rp = str(
            p.resolve()
        ).lower()

        if rp in seen:
            continue

        seen.add(rp)

        files_scanned += 1

        try:
            data = p.read_bytes()
        except OSError:
            continue

        hits = scan_dada(data)

        if not hits:
            continue

        file_item = {
            "path": str(p),
            "size": len(data),
            "sha256": sha256(data),
            "entries": hits,
        }

        dada_files.append(
            file_item
        )

        for rec in hits:

            rec2 = dict(rec)

            rec2["file"] = str(p)
            rec2["file_size"] = len(data)
            rec2["file_sha256"] = sha256(data)

            low = str(p).lower()

            if "6261" in low:
                rec2["score"] += 100

            if "download_agent" in low:
                rec2["score"] += 100

            if "allinone" in low:
                rec2["score"] += 50

            records.append(
                rec2
            )


records.sort(
    key=lambda x: (
        -x["score"],
        x["file"],
        x["offset"],
    )
)

log(
    f"files scanned     = {files_scanned}"
)

log(
    f"files with DADA   = {len(dada_files)}"
)

log(
    f"plausible entries = {len(records)}"
)


# --------------------------------------------------------------------
# E. Best candidates
# --------------------------------------------------------------------

log()
log("=" * 120)
log("E. BEST DA CANDIDATES")
log("=" * 120)

top = records[:50]

if not top:
    log("NONE")

for n, rec in enumerate(top):

    log()
    log(
        f"[{n:02d}] score={rec['score']}"
    )

    log(
        f"file   = {rec['file']}"
    )

    log(
        f"offset = 0x{rec['offset']:X}"
    )

    log(
        f"hw     = 0x{rec['hw_code']:04X} "
        f"({rec['hw_name']})"
    )

    log(
        f"sub/ver/sw = "
        f"0x{rec['hw_sub_code']:04X} / "
        f"0x{rec['hw_version']:04X} / "
        f"0x{rec['sw_version']:04X}"
    )

    log(
        f"pagesize = 0x{rec['pagesize']:X}"
    )

    log(
        f"entry_region_index = "
        f"{rec['entry_region_index']}"
    )

    log(
        f"entry_region_count = "
        f"{rec['entry_region_count']}"
    )

    log(
        f"valid regions = "
        f"{rec['valid_regions']}"
    )

    for r in rec["regions"]:

        stage = ""

        if (
            r["index"]
            == rec["entry_region_index"]
        ):
            stage = " <<< ENTRY/STAGE1"

        elif (
            r["index"]
            == rec["entry_region_index"] + 1
        ):
            stage = " <<< NEXT/STAGE2"

        log(
            f"  region[{r['index']:02d}] "
            f"buf=0x{r['m_buf']:08X} "
            f"len=0x{r['m_len']:08X} "
            f"addr=0x{r['m_start_addr']:08X} "
            f"start_off=0x{r['m_start_offset']:08X} "
            f"sig=0x{r['m_sig_len']:X} "
            f"file_valid={'YES' if r['file_valid'] else 'NO'}"
            f"{stage}"
        )


# --------------------------------------------------------------------
# F. MT6261-specific candidates
# --------------------------------------------------------------------

log()
log("=" * 120)
log("F. MT6261-SPECIFIC CANDIDATES")
log("=" * 120)

mt6261 = [
    r
    for r in records
    if r["hw_code"] == 0x6261
]

log(
    f"count = {len(mt6261)}"
)

two_stage = []

for rec in mt6261:

    stage = rec["entry_region_index"]

    ok = (
        stage < rec["entry_region_count"]
        and stage + 1 < rec["entry_region_count"]
        and rec["regions"][stage]["file_valid"]
        and rec["regions"][stage + 1]["file_valid"]
    )

    if ok:
        two_stage.append(rec)

    log()
    log(
        f"{rec['file']}"
    )

    log(
        f"  entry @ 0x{rec['offset']:X}"
    )

    log(
        f"  region index/count = "
        f"{stage}/{rec['entry_region_count']}"
    )

    log(
        f"  usable stage1+stage2 = "
        f"{'YES' if ok else 'NO'}"
    )


log()
log(
    "MT6261 TWO-STAGE DA CANDIDATE FOUND : "
    + (
        "YES"
        if two_stage
        else "NO"
    )
)


# --------------------------------------------------------------------
# G. Manifest
# --------------------------------------------------------------------

manifest = {
    "schema":
        "S12.9R-mt6261-da-inventory-v1",

    "files_scanned":
        files_scanned,

    "payload_hits":
        payload_hits,

    "download_agent_files":
        download_agent_files,

    "dada_file_count":
        len(dada_files),

    "plausible_dada_entries":
        len(records),

    "mt6261_entries":
        mt6261,

    "mt6261_two_stage_count":
        len(two_stage),

    "device_access":
        False,

    "da_uploaded":
        False,

    "da_jump":
        False,

    "flash_write":
        False,

    "flash_erase":
        False,

    "flash_authorized":
        False,
}

MANIFEST.write_text(
    json.dumps(
        manifest,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)


# --------------------------------------------------------------------
# H. Final classification
# --------------------------------------------------------------------

log()
log("=" * 120)
log("S12.9R RESULT")
log("=" * 120)

log(
    "OFFLINE DA INVENTORY            : PASS"
)

log(
    "mt6261_payload IS FULL DA       : NO / DO NOT ASSUME"
)

log(
    "MT6261 TWO-STAGE DA FOUND       : "
    + (
        "YES"
        if two_stage
        else "NO"
    )
)

log(
    "EXACT ALTICE F2 DA IDENTIFIED   : NO"
)

log(
    "DA UPLOAD AUTHORIZED            : NO"
)

log(
    "DEVICE WRITE/ERASE AUTHORIZED   : NO"
)

log(
    "FLASH AUTHORIZED                : NO"
)

REPORT.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)

print()
print("Report  :", REPORT)
print("Manifest:", MANIFEST)
