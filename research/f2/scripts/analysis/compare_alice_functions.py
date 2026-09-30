#!/usr/bin/env python3
import argparse
import csv
from collections import defaultdict

def load(path):
    rows = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            r["body_bytes"] = int(r["body_bytes"])
            r["instructions"] = int(r["instructions"])
            r["calls"] = int(r["calls"])
            r["returns"] = int(r["returns"])
            r["tokens"] = tuple(x for x in r["mnemonics"].split(",") if x)
            rows.append(r)
    return rows

def ngrams(tokens, n=4):
    if len(tokens) < n:
        return {tokens} if tokens else set()
    return {tokens[i:i+n] for i in range(len(tokens)-n+1)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qmobile", required=True)
    ap.add_argument("--altice", required=True)
    ap.add_argument("--out", default="alice_function_compare.txt")
    args = ap.parse_args()

    q = load(args.qmobile)
    a = load(args.altice)

    ahash = defaultdict(list)
    for r in a:
        ahash[r["mnemonic_sha256"]].append(r)

    exact_q = []
    unique_q = []
    for r in q:
        if r["mnemonic_sha256"] in ahash:
            exact_q.append(r)
        else:
            unique_q.append(r)

    # Inverted n-gram index for approximate function matching.
    inv = defaultdict(set)
    aset = []
    for idx, r in enumerate(a):
        gs = ngrams(r["tokens"])
        aset.append(gs)
        for g in gs:
            inv[g].add(idx)

    candidates = []
    for qr in unique_q:
        if qr["instructions"] < 8:
            continue
        qg = ngrams(qr["tokens"])
        counts = defaultdict(int)
        for g in qg:
            for idx in inv.get(g, ()):
                counts[idx] += 1

        best = None
        for idx, overlap in counts.items():
            ar = a[idx]

            # Avoid comparing wildly different function sizes.
            ratio = ar["instructions"] / max(1, qr["instructions"])
            if ratio < 0.55 or ratio > 1.8:
                continue

            ag = aset[idx]
            union = len(qg | ag)
            jac = overlap / union if union else 0.0

            # Reward similar call counts / sizes a little.
            call_penalty = abs(qr["calls"] - ar["calls"]) * 0.015
            size_penalty = abs(qr["instructions"] - ar["instructions"]) / max(
                qr["instructions"], ar["instructions"], 1
            ) * 0.08
            score = jac - call_penalty - size_penalty

            if best is None or score > best[0]:
                best = (score, jac, ar)

        if best and best[1] >= 0.35:
            candidates.append((best[0], best[1], qr, best[2]))

    candidates.sort(key=lambda x: (x[1], x[2]["instructions"]), reverse=True)

    with open(args.out, "w", encoding="utf-8") as out:
        out.write("=== Résumé ===\n")
        out.write(f"Fonctions QMobile : {len(q)}\n")
        out.write(f"Fonctions Altice  : {len(a)}\n")
        out.write(f"QMobile avec empreinte exacte trouvée dans Altice : {len(exact_q)}\n")
        out.write(f"QMobile sans empreinte exacte dans Altice         : {len(unique_q)}\n")
        out.write("\n")

        out.write("=== Candidats proches QMobile -> Altice ===\n")
        out.write("But: repérer une fonction presque identique, mais avec des appels en plus/en moins.\n\n")

        for score, jac, qr, ar in candidates[:150]:
            call_delta = qr["calls"] - ar["calls"]
            inst_delta = qr["instructions"] - ar["instructions"]
            out.write(
                f"Q {qr['entry']} {qr['name']} "
                f"ins={qr['instructions']} calls={qr['calls']}  <->  "
                f"A {ar['entry']} {ar['name']} "
                f"ins={ar['instructions']} calls={ar['calls']}  "
                f"jaccard={jac:.3f} "
                f"dIns={inst_delta:+d} dCalls={call_delta:+d}\n"
            )

        out.write("\n=== QMobile-only grandes fonctions sans proche évident ===\n")
        no_near_entries = {x[2]["entry"] for x in candidates}
        rest = [r for r in unique_q if r["entry"] not in no_near_entries and r["instructions"] >= 20]
        rest.sort(key=lambda r: (r["instructions"], r["calls"]), reverse=True)
        for r in rest[:100]:
            out.write(
                f"{r['entry']} {r['name']} "
                f"ins={r['instructions']} calls={r['calls']} bytes={r['body_bytes']}\n"
            )

    print("QMobile functions:", len(q))
    print("Altice functions :", len(a))
    print("Exact Q->A       :", len(exact_q))
    print("QMobile unique   :", len(unique_q))
    print("Near candidates  :", len(candidates))
    print("Report           :", args.out)

if __name__ == "__main__":
    main()
