#!/usr/bin/env python3
"""Coarse mnemonic-sequence comparison for QMobile playlist helpers vs Altice ALICE."""
import json
from difflib import SequenceMatcher
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
REPORTS = BASE / "work" / "ghidra" / "alice_reports"
Q_PATH = REPORTS / "qmobile_normalized_details.jsonl"
A_PATH = REPORTS / "altice_details.jsonl"
TARGETS = ("103213dc", "103c8920", "103a45e4", "102f6620")


def load(path):
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def mnemonics(function):
    return [ins.get("mnemonic", "?") for ins in function.get("instructions", [])]


def main():
    q_funcs = {f["entry"].lower(): f for f in load(Q_PATH)}
    a_funcs = load(A_PATH)
    print("Exploratory only: mnemonic similarity cannot establish semantic equivalence.")
    for address in TARGETS:
        q = q_funcs.get(address)
        if not q:
            print(f"\nQ {address}: missing from normalized detail export")
            continue
        q_seq = mnemonics(q)
        scored = []
        for a in a_funcs:
            a_seq = mnemonics(a)
            if not a_seq or not q_seq:
                continue
            length_ratio = min(len(q_seq), len(a_seq)) / max(len(q_seq), len(a_seq))
            if length_ratio < 0.55:
                continue
            ratio = SequenceMatcher(None, q_seq, a_seq, autojunk=False).ratio()
            scored.append((ratio, length_ratio, a, len(a_seq)))
        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        print(f"\nQ {address} {q.get('name')} ins={len(q_seq)} calls={sum(i.get('call', False) for i in q['instructions'])}")
        for ratio, length_ratio, a, n in scored[:8]:
            calls = sum(i.get("call", False) for i in a["instructions"])
            print(f"  A {a['entry']} {a.get('name')} ins={n} calls={calls} mnemonic_ratio={ratio:.3f} length_ratio={length_ratio:.3f}")


if __name__ == "__main__":
    main()
