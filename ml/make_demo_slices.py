#!/usr/bin/env python3
"""ml/make_demo_slices.py — build small, upload-ready CICIDS demo CSVs.

Full CICIDS files are 70–170 MB and each discovers ~9 incidents (heavy Gemini
quota if all auto-investigated). For a fast, reliable, low-quota demo, slice each
source file to ONE clean attack: the CICFlowMeter header + a small BENIGN sample
+ the attack-labelled flows of interest. Detection is unchanged (detectors never
read Label; Label is used HERE only to select rows). stdlib only.

Writes data/cicids/demo/*.csv.  Usage: python3 ml/make_demo_slices.py
"""
import csv, os, sys

csv.field_size_limit(1 << 24)
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
SRC = os.path.join(ROOT, "data", "cicids")
OUT = os.path.join(ROOT, "data", "cicids", "demo")

# (source file, attack-label substrings, output name, benign cap, attack cap)
SLICES = [
    ("Tuesday-WorkingHours.pcap_ISCX.csv", ("PATATOR",),
     "demo_bruteforce_T1110.csv", 1500, 5000),
    ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", ("DDOS",),
     "demo_ddos_T1498.csv", 1500, 6000),
    ("Friday-WorkingHours-Morning.pcap_ISCX.csv", ("BOT",),
     "demo_botnet_T1071.csv", 1500, 4000),
]

def build(src_file, subs, out_name, benign_cap, attack_cap):
    src = os.path.join(SRC, src_file)
    if not os.path.exists(src):
        print(f"  ! missing {src_file}", file=sys.stderr); return
    with open(src, "r", encoding="latin-1", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        li = next((i for i, h in enumerate(header)
                   if h.strip().lower() == "label"), len(header) - 1)
        kept, nb, na = [], 0, 0
        for row in reader:
            if len(row) <= li:
                continue
            lab = row[li].strip().upper()
            if lab == "BENIGN":
                if nb < benign_cap:
                    kept.append(row); nb += 1
            elif any(s in lab for s in subs):
                if na < attack_cap:
                    kept.append(row); na += 1
            if nb >= benign_cap and na >= attack_cap:
                break
    os.makedirs(OUT, exist_ok=True)
    out = os.path.join(OUT, out_name)
    with open(out, "w", encoding="latin-1", newline="") as fh:
        w = csv.writer(fh); w.writerow(header); w.writerows(kept)
    print(f"  {out_name}: benign={nb} attack={na} rows={len(kept)} "
          f"size={os.path.getsize(out) // 1024}KB")


def main():
    print(f"writing demo slices to {OUT}")
    for args in SLICES:
        build(*args)


if __name__ == "__main__":
    main()
