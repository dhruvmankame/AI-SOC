#!/usr/bin/env python3
"""
analyze.py  (AI-SOC) — analyze ONE uploaded flow CSV -> JSON (no DB, no SQL).

The seed pipeline (ingest_cicids.py) is a fixed 3-file CICIDS demo. This is its
dynamic sibling: one uploaded CICFlowMeter/CICIDS flow CSV in, a batch of
DYNAMICALLY-DISCOVERED incidents out, as JSON on stdout. The Node backend
(agents/src/server.ts) does the actual DB writes (the browser is RLS read-only
and Python is stdlib-only — no psycopg), then auto-runs the agent graph.

Reuses the SAME behavioural detectors as the seed via soccore (nothing here
reads the ground-truth Label for DETECTION; Label, if present, is used only for
an honest bonus P/R/F1). Stdlib only; the CSV is streamed twice.

Incident discovery is deliberately TWO steps so one flow never leaks into two
incidents:
  1. run the detectors over every flow -> signals (families: brute_force / flood
     / beacon), keyed into clusters: brute_force->(src,dst), flood->(dst,dport),
     beacon->(external C2 dst).
  2. assign each event to EXACTLY ONE incident: pick the owning family by fixed
     priority brute_force > beacon > flood (a port-22 flood is credential access,
     not DDoS — and note FLOOD's 0.97 score cap > BRUTEFORCE's 0.95, so score
     alone would misassign), then higher detector score, then key string. One
     flow can fire two families (src->dst:22 with >=3000 flows trips BOTH
     brute_force and flood); single-owner assignment is what stops that event
     landing in two incidents' event_ids and re-introducing cross-scenario leak.

Usage:  python3 ml/analyze.py <csv_path> [--batch <uuid>] [--label <text>]
Output: JSON {batch, incidents, incident_entities, events, signals, alerts,
              rules, attack_kb, eval?}  OR  {error} on a non-flow / bad file.
"""
import csv, os, sys, json, math, uuid, hashlib, argparse
from collections import Counter
from datetime import datetime, timezone

from soccore import (
    NS, RULES, ATTACK_KB, TECH, FAMILY_PRIORITY, FAMILY_TECH, FAMILY_TITLE,
    parse_ts, open_rows, g, detect, build_aggregates,
    family_of, cluster_key, sev_band,
    classify_attack_label, is_benign_label, label_rule_rows,
    LABEL_SCORE, LABEL_FAMILY_PREFIX, HEADER_ALIASES,
)

csv.field_size_limit(1 << 24)

SCEN = "upload"                 # single implicit scenario for one uploaded file
REQUIRED_COLS = ("Source IP", "Destination IP", "Destination Port", "Timestamp")
CAP_PER_INCIDENT = 80           # stored attack events per incident (agent reads <=60)
ALERT_EVENT_CAP = 60            # alert.event_ids cap == getIncidentEvents default limit
CAP_BENIGN = 300                # small benign context sample (display only; eval uses ALL flows)
CAP_ENTITY_SET = 12             # capped distinct srcs listed as flood actors / beacon victims
MAX_INCIDENTS = 12              # auto-investigation spends LLM quota per incident; a
                                # many-class dataset is truncated to the top-N by risk and
                                # the drop is reported (never silently).


def fail(msg):
    """Emit a clean JSON error (never a stack trace) and exit; the server parses
    stdout and branches on the `error` key."""
    print(json.dumps({"error": msg}))
    sys.exit(0)


def _event_id(rown, row, idx, batch_id):
    return str(uuid.uuid5(NS, f"{batch_id}:{rown}:{g(row, idx, 'Flow ID')}"))


def _event(row, idx, ts, eid, src, dst, dport, sigs, has_label, is_attack):
    top = max((s["score"] for s in sigs), default=0.0)
    mitre = sorted({TECH[s["detector_ref"]] for s in sigs if s["detector_ref"] in TECH})
    raw = json.dumps({
        "flow_id": g(row, idx, "Flow ID"), "sport": g(row, idx, "Source Port"),
        "dport": dport, "proto": g(row, idx, "Protocol"),
        "duration_us": g(row, idx, "Flow Duration"),
        "fwd_pkts": g(row, idx, "Total Fwd Packets"),
        "bwd_pkts": g(row, idx, "Total Backward Packets"),
        "flow_pkts_s": g(row, idx, "Flow Packets/s"),
    }, separators=(",", ":"))
    return {
        "event_id": eid, "ts": ts, "source_type": "network",
        "vendor": "CICFlowMeter", "product": "flow-upload", "class_uid": 4001,
        "category": "network", "activity": "network_flow",
        "severity": sev_band(top), "outcome": "unknown",
        "src_ip": src, "dst_ip": dst, "template_id": "NETFLOW",
        "template_text": f"flow {src}:{g(row, idx, 'Source Port')} -> {dst}:{dport} "
                         f"proto {g(row, idx, 'Protocol')}",
        "parser_confidence": 1.0, "mitre_tags": mitre, "raw": raw,
        "raw_hash": hashlib.sha1(eid.encode()).hexdigest(),
        "gt_label": ("attack" if is_attack else "benign") if has_label else None,
        "gt_scenario": None,
    }


def assign_owner(sigs, src, dst, dport):
    """Step 2 — the SINGLE owning (family, cluster_key) for an event's signals.
    Sort key: family priority (brute_force > beacon > flood) FIRST — this is the
    domain reading and, crucially, is NOT score: FLOOD caps at 0.97 > BRUTEFORCE
    0.95, so an argmax on score would file a port-22 credential flood under DDoS.
    Then higher detector score, then the key string for determinism."""
    best = None  # ((priority, -score, keystr), family, key)
    for s in sigs:
        fam = family_of(s["detector_ref"])
        if fam is None:
            continue
        key = cluster_key(fam, src, dst, dport)
        cand = (FAMILY_PRIORITY[fam], -s["score"], str(key))
        if best is None or cand < best[0]:
            best = (cand, fam, key)
    return None if best is None else (best[1], best[2])


def _eval(cm):
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
            "note": "detectors evaluated on ALL flows; predicted-attack = >=1 behavioural signal"}


def _build(inc, events, signals, batch_id, label, path, cm, has_label, std):
    """Turn the per-cluster accumulators into incidents + entities + alerts.
    `inc` may be empty (benign file) — then only the (benign) events carry over."""
    items = list(inc.values())
    for a in items:
        a["risk"] = round(min(96.0, 60 + 12 * math.log10(a["flow_count"] + 1)), 1)
    # order by risk desc so INC-...-NNN codes rank most-severe first; deterministic
    items.sort(key=lambda a: (-a["risk"], FAMILY_PRIORITY[a["family"]], str(a["key"])))
    # Auto-investigation spends LLM quota per incident. A dataset with many
    # attack classes is truncated to the highest-risk MAX_INCIDENTS, and the
    # drop is REPORTED (never silent) so the UI can say what was not analysed.
    std["incidents_discovered"] = len(items)
    std["incidents_truncated"] = max(0, len(items) - MAX_INCIDENTS)
    if std["incidents_truncated"]:
        items = items[:MAX_INCIDENTS]

    bhex = batch_id.replace("-", "")[:6]        # per-batch discriminator: code is UNIQUE globally
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    incidents, entities, alerts = [], [], []
    for n0, a in enumerate(items, 1):
        fam, ckey = a["family"], a["key"]
        iid = str(uuid.uuid5(NS, f"{batch_id}:{fam}:{ckey}"))
        contribs = {k: round(v, 3) for k, v in a["contribs"].items()}
        eids = a["event_ids"][:ALERT_EVENT_CAP]
        # How this incident is evidenced — carried through to the UI and to the
        # verifier's Stage-3 confidence so an annotation-only finding is never
        # presented as if an independent detector had confirmed it.
        bflows = a.get("behavioural_flows", 0)
        basis = ("behavioural" if bflows == a["flow_count"]
                 else "annotation-only" if bflows == 0
                 else "behavioural+annotation")
        incidents.append({
            "incident_id": iid, "code": f"INC-{day}-{bhex}-{n0:03d}",
            "title": FAMILY_TITLE[fam], "risk_score": a["risk"],
            "risk_factors": {"attack_flows": a["flow_count"],
                             "detector_confidence": max(contribs.values(), default=0.0),
                             "asset_criticality": 0.7,
                             "behavioural_flows": bflows,
                             "corroboration_pct": round(100.0 * bflows / a["flow_count"], 1) if a["flow_count"] else 0.0,
                             "evidence_basis": basis},
            "mitre_techniques": [FAMILY_TECH[fam]], "summary": None, "family": fam,
        })
        seen = set()
        def _ent(val, role):
            k = (val, role)
            if val and k not in seen:
                seen.add(k)
                entities.append({"incident_id": iid, "entity_type": "ip",
                                 "entity_value": val, "role": role})
        if fam == "brute_force":                 # key=(src,dst)
            _ent(ckey[0], "actor"); _ent(ckey[1], "target")
        elif fam == "flood":                     # key=(dst,dport); srcs = attackers
            _ent(ckey[0], "target")
            for s in sorted(a["srcs"]):
                _ent(s, "actor")
        elif fam == "beacon":                    # key=(c2_dst,); srcs = infected internal hosts
            _ent(ckey[0], "actor")
            for s in sorted(a["srcs"]):
                _ent(s, "victim")
        elif fam.startswith(LABEL_FAMILY_PREFIX):  # key=(dst,); srcs = attackers
            _ent(ckey[0], "target")
            for s in sorted(a["srcs"]):
                _ent(s, "actor")
        # one deduplicated alert per incident (noisy-OR over contributing detectors)
        conf = 1.0
        for sc in contribs.values():
            conf *= (1 - sc)
        alerts.append({
            "alert_id": str(uuid.uuid5(NS, f"{batch_id}:alert:{fam}:{ckey}")),
            "title": FAMILY_TITLE[fam], "severity": "high", "confidence": round(1 - conf, 3),
            "detector": max(contribs, key=contribs.get) if contribs else "rule",
            "contributions": contribs, "entity": ckey[0], "event_ids": eids,
            "correlation_count": a["flow_count"], "status": "new", "incident_id": iid,
        })

    return {
        "batch": {"batch_id": batch_id, "label": label or os.path.basename(path),
                  "source_filename": os.path.basename(path), "event_count": len(events),
                  "incident_count": len(incidents), "status": "detected"},
        "standardization": std,
        "incidents": incidents, "incident_entities": entities,
        "events": events, "signals": signals, "alerts": alerts,
        "rules": ([dict(rule_id=r[0], title=r[1], detector=r[2], mitre_tags=r[3], severity=r[4]) for r in RULES]
                  + [dict(rule_id=r[0], title=r[1], detector=r[2], mitre_tags=r[3], severity=r[4]) for r in label_rule_rows()]),
        "attack_kb": [dict(technique_id=t[0], name=t[1], tactic=t[2], description=t[3]) for t in ATTACK_KB],
        "eval": _eval(cm) if has_label else None,
    }


def _header_of(path):
    """The raw header row, for the Stage-1 standardization report."""
    with open(path, "r", encoding="latin-1", newline="") as fh:
        return [h.strip() for h in next(csv.reader(fh))]


def analyze(path, batch_id, label):
    # ---- header validation: fail clean on a non-flow file -------------------
    try:
        f, reader, idx = open_rows(path)
    except FileNotFoundError:
        fail(f"file not found: {path}")
    except Exception as e:                       # unreadable / not a CSV at all
        fail(f"could not read CSV: {e}")
    missing = [c for c in REQUIRED_COLS if c not in idx]
    f.close()
    if missing:
        fail("unsupported flow CSV schema. Expected CICIDS/CICFlowMeter-style network-flow columns "
             "(Source/Src IP, Destination/Dst IP, Destination/Dst Port, Timestamp). "
             "Common header aliases are accepted. Missing canonical fields: " + ", ".join(missing))
    has_label = "Label" in idx

    # ---- Stage 1: standardization report ------------------------------------
    # What the ingestion layer actually did to this file: which of the source
    # columns it recognised and bound to each canonical field. This is the
    # deterministic "convert any dataset to a standard form" stage, surfaced so
    # it is inspectable rather than implicit.
    header = _header_of(path)
    std = {
        "source_columns": len(header),
        "source_column_names": header[:40],
        "canonical_mapping": {
            c: (header[idx[c]] if c in idx and idx[c] < len(header) else None)
            for c in ("Source IP", "Destination IP", "Destination Port",
                      "Timestamp", "Protocol", "Label")
        },
        "label_column_present": has_label,
    }

    # ---- pass 1: behavioural aggregates over ALL flows (shared with the seed)
    aggs = build_aggregates([(path, SCEN)])

    # ---- pass 2: detect -> single-owner assign -> sample-store --------------
    inc = {}                       # (family,key) -> accumulator
    events, signals = [], []
    stored_per_inc = Counter()
    cm = Counter()                 # eval confusion matrix (only used if has_label)
    benign_seen = benign_stored = 0
    dropped_bad_ts = 0             # Stage-1 standardization report
    label_flows = Counter()        # attack_class -> annotated flow count
    corroborated_flows = Counter() # attack_class -> annotated flows a real detector ALSO caught
    btotal = aggs["benign"].get(SCEN, 0)
    bstride = max(1, btotal // CAP_BENIGN)       # spread the benign sample across the file

    f, reader, idx = open_rows(path)
    rown = 0
    valid_ts_rows = 0
    for row in reader:
        rown += 1
        if rown % 50000 == 0:
            print(f"pass 2/2 (detect): {rown:,} rows", file=sys.stderr, flush=True)
        if len(row) < 4:
            continue
        src = g(row, idx, "Source IP"); dst = g(row, idx, "Destination IP")
        if not src or not dst:
            continue
        dport = g(row, idx, "Destination Port")
        sigs = detect(row, idx, aggs, SCEN)
        # EVAL INTEGRITY: `pred` is the BEHAVIOURAL verdict and is captured HERE,
        # before the annotation-derived signal is appended below. If a label
        # signal were counted as a prediction the confusion matrix would be
        # scoring the label against itself and would report a meaningless
        # perfect F1. The reported P/R/F1 therefore always measures the real
        # detectors only.
        pred = len(sigs) > 0

        is_attack = None
        raw_label = g(row, idx, "Label") if has_label else ""
        if has_label:
            is_attack = not is_benign_label(raw_label)
            cm["tp" if (is_attack and pred) else "fn" if (is_attack and not pred)
               else "fp" if (not is_attack and pred) else "tn"] += 1

        ts = parse_ts(g(row, idx, "Timestamp"))
        if ts is None:
            # events.ts is NOT NULL — a flow with an unparseable timestamp cannot be stored.
            dropped_bad_ts += 1
            continue
        valid_ts_rows += 1

        # ---- Stage-1 attack-class bridge -----------------------------------
        # A labelled attack the behavioural detectors cannot see (SQL injection,
        # XSS, port scan, ...) still becomes a signal — flagged as an ANNOTATION
        # so nothing downstream mistakes it for independent detection.
        if has_label and is_attack:
            lbl = classify_attack_label(raw_label)
            if lbl is not None:
                label_flows[lbl["attack_class"]] += 1
                if pred:
                    corroborated_flows[lbl["attack_class"]] += 1
                sigs = sigs + [dict(
                    detector="label", detector_ref=lbl["detector_ref"], score=LABEL_SCORE,
                    reason=(f"dataset-annotated '{lbl['raw_label']}' -> {lbl['attack_class']} "
                            f"({lbl['technique']}); annotation supplied by the dataset, "
                            f"NOT independent behavioural detection"))]

        if not sigs:                             # benign / no-signal: strided context sample
            benign_seen += 1
            if benign_stored < CAP_BENIGN and benign_seen % bstride == 0:
                eid = _event_id(rown, row, idx, batch_id)
                events.append(_event(row, idx, ts, eid, src, dst, dport, sigs, has_label, is_attack))
                benign_stored += 1
            continue

        owner = assign_owner(sigs, src, dst, dport)   # step 2: exactly one incident
        if owner is None:
            continue
        acc = inc.get(owner)
        if acc is None:
            acc = inc[owner] = {"family": owner[0], "key": owner[1], "flow_count": 0,
                                "behavioural_flows": 0,
                                "top_score": 0.0, "contribs": {}, "srcs": set(), "event_ids": []}
        acc["flow_count"] += 1                   # TRUE (uncapped) attack-flow count -> risk
        if pred:
            acc["behavioural_flows"] += 1        # an independent detector saw this flow too
        for s in sigs:
            acc["contribs"][s["detector_ref"]] = max(acc["contribs"].get(s["detector_ref"], 0.0), s["score"])
            acc["top_score"] = max(acc["top_score"], s["score"])
        if len(acc["srcs"]) < CAP_ENTITY_SET:
            acc["srcs"].add(src)
        if stored_per_inc[owner] < CAP_PER_INCIDENT:   # store a capped sample of this incident
            eid = _event_id(rown, row, idx, batch_id)
            events.append(_event(row, idx, ts, eid, src, dst, dport, sigs, has_label, is_attack))
            for s in sigs:
                signals.append(dict(event_id=eid, **s))
            acc["event_ids"].append(eid)
            stored_per_inc[owner] += 1
    f.close()
    if valid_ts_rows == 0:
        fail("CSV schema was recognized, but no usable timestamped flow rows were found. "
             "Use CICIDS/CICFlowMeter-style timestamps, ISO-8601, or Unix epoch seconds/milliseconds.")

    # Finish the Stage-1 report with what the pass actually produced, including
    # the corroboration rate per attack class: of the flows the dataset annotated
    # as this attack, how many an INDEPENDENT behavioural detector also flagged.
    std["rows_read"] = rown
    std["rows_standardized"] = valid_ts_rows
    std["rows_dropped_unparseable_timestamp"] = dropped_bad_ts
    std["attack_classes"] = [
        {"attack_class": cls,
         "annotated_flows": n,
         "corroborated_by_detector": corroborated_flows.get(cls, 0),
         "corroboration_pct": round(100.0 * corroborated_flows.get(cls, 0) / n, 1) if n else 0.0}
        for cls, n in sorted(label_flows.items(), key=lambda kv: -kv[1])
    ]
    return _build(inc, events, signals, batch_id, label, path, cm, has_label, std)


def main():
    ap = argparse.ArgumentParser(description="Analyze one flow CSV -> incidents JSON")
    ap.add_argument("csv_path")
    ap.add_argument("--batch", default=None, help="batch uuid (server-supplied); generated if absent")
    ap.add_argument("--label", default=None, help="human label for the batch")
    args = ap.parse_args()
    batch_id = args.batch or str(uuid.uuid4())
    try:
        uuid.UUID(batch_id)                      # it becomes a uuid PK + id-namespacing seed
    except ValueError:
        fail(f"invalid --batch uuid: {batch_id}")
    out = analyze(args.csv_path, batch_id, args.label)
    json.dump(out, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()



