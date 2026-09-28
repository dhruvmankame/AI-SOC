#!/usr/bin/env python3
"""
ingest_cicids.py  (AI-SOC)  — REAL DATA pipeline

Replaces the synthetic generator with real-world CICIDS2017 network flows
(Canadian Institute for Cybersecurity, UNB — an open dataset widely used in
intrusion-detection research). We target THREE attack types:

    brute_force  — FTP-Patator / SSH-Patator   (Tuesday)      -> ATT&CK T1110
    ddos         — LOIC HTTP flood              (Fri afternoon)-> ATT&CK T1498
    botnet       — Ares C2 beaconing            (Fri morning)  -> ATT&CK T1071

Pipeline (stdlib only, streaming — the CSVs are 75-175 MB each):

    labelled flow CSVs
      -> pass 1: build behavioural aggregates (per src->dst:port flow counts)
      -> pass 2: feature-based detectors (NOT reading the Label) -> signals
                 + honest evaluation vs the ground-truth Label (precision/recall/F1)
                 + reproducible sample of flows stored as `events`
      -> build 3 incident shells (entities only; evidence/timeline/report are
         produced later BY THE AGENTS) + link alerts
      -> data/cicids_seed.sql  (+ data/cicids_eval.json)

Detectors are behavioural aggregates, not a lookup of the label:
  R-NET-BRUTEFORCE : many flows from one src to one dst on FTP(21)/SSH(22)
  R-NET-FLOOD      : one src->dst:port receiving a flood of flows (+ pkt-rate z)
  R-NET-BEACON     : internal host repeatedly contacting one external dst (C2),
                     boosted when several internal hosts fan-in to that dst
"""
import csv, os, sys, json, math, uuid, hashlib, statistics
from collections import defaultdict, Counter
from datetime import datetime, timezone

from soccore import (
    NS, BF_PORTS, BF_MIN_FLOWS, FLOOD_MIN_FLOWS, FLOOD_EXCLUDE,
    BEACON_MIN_FLOWS, BEACON_MIN_FANIN, COMMON_PORTS, CAP_ATTACK, CAP_BENIGN,
    TECH, SCEN_TECH, SCEN_TITLE, ECOLS, RULES, ATTACK_KB,
    is_internal, parse_ts, open_rows, g, fnum, detect, build_aggregates,
    q, arr, sev_band,
)

csv.field_size_limit(1 << 24)

HERE = os.path.dirname(__file__)
CICDIR = os.path.join(HERE, "..", "data", "cicids")
SEED_SQL = os.path.join(HERE, "..", "data", "cicids_seed.sql")
EVAL_JSON = os.path.join(HERE, "..", "data", "cicids_eval.json")

FILES = [
    ("Tuesday-WorkingHours.pcap_ISCX.csv", "brute_force"),
    ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "ddos"),
    ("Friday-WorkingHours-Morning.pcap_ISCX.csv", "botnet"),
]


# ------------------------------------------------------- pass 2: evaluate + sample + build
def run(aggs):
    events, signals = [], []                       # stored sample
    stored_attack = Counter(); stored_benign = Counter()
    cm = defaultdict(lambda: Counter())            # scenario -> {tp,fp,fn,tn}
    entity_hits = defaultdict(lambda: Counter())   # scenario -> Counter(event_id) placeholder
    scen_events = defaultdict(list)                # scenario -> stored attack event_ids
    # sampling stride so stored benign is spread across each file, not just the head
    stride = {scen: max(1, aggs["benign"][scen] // CAP_BENIGN) for _, scen in FILES}
    benign_seen = Counter()

    for fname, scen in FILES:
        path = os.path.join(CICDIR, fname)
        f, reader, idx = open_rows(path)
        rown = 0
        for row in reader:
            rown += 1
            if len(row) < 20:
                continue
            src = g(row, idx, "Source IP"); dst = g(row, idx, "Destination IP")
            if not src or not dst:
                continue
            label = g(row, idx, "Label").upper()
            is_attack = label != "BENIGN"
            sigs = detect(row, idx, aggs, scen)
            pred = len(sigs) > 0
            # honest confusion matrix over ALL flows
            key = "tp" if (is_attack and pred) else "fn" if (is_attack and not pred) \
                else "fp" if (not is_attack and pred) else "tn"
            cm[scen][key] += 1

            # reservoir-ish sampling for STORAGE (metrics already counted above)
            store = False
            if is_attack and stored_attack[scen] < CAP_ATTACK:
                store = True; stored_attack[scen] += 1
            elif not is_attack:
                benign_seen[scen] += 1
                if stored_benign[scen] < CAP_BENIGN and benign_seen[scen] % stride[scen] == 0:
                    store = True; stored_benign[scen] += 1
            if not store:
                continue

            dport = g(row, idx, "Destination Port")
            proto = g(row, idx, "Protocol")
            ts = parse_ts(g(row, idx, "Timestamp"))
            eid = str(uuid.uuid5(NS, f"{scen}:{rown}:{g(row, idx, 'Flow ID')}"))
            top = max((s["score"] for s in sigs), default=0.0)
            mitre = sorted({TECH[s["detector_ref"]] for s in sigs if s["detector_ref"] in TECH})
            raw = json.dumps({
                "flow_id": g(row, idx, "Flow ID"), "sport": g(row, idx, "Source Port"),
                "dport": dport, "proto": proto,
                "duration_us": g(row, idx, "Flow Duration"),
                "fwd_pkts": g(row, idx, "Total Fwd Packets"),
                "bwd_pkts": g(row, idx, "Total Backward Packets"),
                "flow_pkts_s": g(row, idx, "Flow Packets/s"),
            }, separators=(",", ":"))
            events.append({
                "event_id": eid, "ts": ts, "source_type": "network",
                "vendor": "CICFlowMeter", "product": "CICIDS2017", "class_uid": 4001,
                "category": "network", "activity": "network_flow",
                "severity": sev_band(top), "outcome": "unknown",
                "src_ip": src, "dst_ip": dst, "template_id": "NETFLOW",
                "template_text": f"flow {src}:{g(row, idx, 'Source Port')} -> {dst}:{dport} proto {proto}",
                "parser_confidence": 1.0, "mitre_tags": mitre, "raw": raw,
                "raw_hash": hashlib.sha1((eid).encode()).hexdigest(),
                "gt_label": "attack" if is_attack else "benign",
                "gt_scenario": scen if is_attack else None,
            })
            for s in sigs:
                signals.append(dict(event_id=eid, **s))
            if is_attack:
                scen_events[scen].append(eid)
        f.close()
    return events, signals, cm, scen_events


def main():
    print("pass 1: building behavioural aggregates over ALL flows ...", flush=True)
    aggs = build_aggregates([(os.path.join(CICDIR, f), scen) for f, scen in FILES])
    print("pass 2: detecting + evaluating + sampling ...", flush=True)
    events, signals, cm, scen_events = run(aggs)

    # per-event scenario map, for per-scenario alert contributions
    escen = {e["event_id"]: e["gt_scenario"] for e in events}
    contrib = defaultdict(dict)          # scenario -> {detector_ref: max score}
    for s in signals:
        sc = escen.get(s["event_id"])
        if sc:
            contrib[sc][s["detector_ref"]] = max(contrib[sc].get(s["detector_ref"], 0), s["score"])

    # data-driven key entities (keys are (scenario, ...))
    bf_key = max((k for k in aggs["bf"] if k[0] == "brute_force"), key=aggs["bf"].get)
    flood_key = max((k for k in aggs["flood"] if k[0] == "ddos" and k[3] not in FLOOD_EXCLUDE
                     and aggs["flood"][k] >= FLOOD_MIN_FLOWS), key=aggs["flood"].get)
    # C2 = external dst in the botnet capture with fan-in>=3, most total beacon flows
    c2_cands = [d for (s, d) in aggs["beacon_srcs"]
                if s == "botnet" and len(aggs["beacon_srcs"][(s, d)]) >= BEACON_MIN_FANIN]
    c2 = max(c2_cands, key=lambda d: aggs["beacon_total"][("botnet", d)])
    infected = sorted(aggs["beacon_srcs"][("botnet", c2)])
    ENT = {
        "brute_force": {"attacker": bf_key[1], "victim": bf_key[2]},
        "ddos": {"attacker": flood_key[1], "victim": flood_key[2]},
        "botnet": {"c2": c2, "infected": infected},
    }

    incidents, inc_entities, alerts = [], [], []
    for scen in ("brute_force", "ddos", "botnet"):
        iid = str(uuid.uuid5(NS, "incident:" + scen))
        tp = cm[scen]["tp"]
        risk = round(min(96.0, 60 + 12 * math.log10(tp + 1)), 1)
        code = {"brute_force": "INC-2017-0001", "ddos": "INC-2017-0002", "botnet": "INC-2017-0003"}[scen]
        incidents.append({
            "incident_id": iid, "code": code, "title": SCEN_TITLE[scen],
            "risk_score": risk,
            "risk_factors": json.dumps({"attack_flows": tp, "detector_confidence": max(contrib[scen].values(), default=0),
                                        "asset_criticality": 0.7}),
            "mitre_techniques": SCEN_TECH[scen],
        })
        if scen == "botnet":
            inc_entities.append((iid, "ip", ENT[scen]["c2"], "actor"))
            for h in infected[:8]:
                inc_entities.append((iid, "ip", h, "victim"))
        else:
            inc_entities.append((iid, "ip", ENT[scen]["attacker"], "actor"))
            inc_entities.append((iid, "ip", ENT[scen]["victim"], "target"))
        # one deduplicated alert per scenario (noisy-OR over contributing detectors)
        cc = contrib[scen]
        conf = 1.0
        for sc in cc.values():
            conf *= (1 - sc)
        conf = round(1 - conf, 3)
        entity = ENT[scen]["c2"] if scen == "botnet" else ENT[scen]["attacker"]
        primary = max(cc, key=cc.get) if cc else "rule"
        alerts.append({
            "alert_id": str(uuid.uuid5(NS, "alert:" + scen)),
            "title": SCEN_TITLE[scen], "severity": "high", "confidence": conf,
            "detector": primary, "contributions": json.dumps(cc),
            "entity": entity, "event_ids": scen_events[scen][:60],
            "correlation_count": tp, "status": "new", "incident_id": iid,
        })
    emit(events, signals, incidents, inc_entities, alerts)
    report(cm, events, signals)


def emit(events, signals, incidents, inc_entities, alerts):
    L = ["-- generated by ml/ingest_cicids.py  (CICIDS2017 real flows)",
         "begin;",
         "truncate events, signals, alerts, incidents, incident_entities, "
         "evidence, agent_runs, incident_timeline restart identity cascade;"]
    for i in incidents:
        L.append(
            "insert into incidents (incident_id,code,title,risk_score,risk_factors,"
            "status,approval_state,mitre_techniques,summary) values "
            f"({q(i['incident_id'])},{q(i['code'])},{q(i['title'])},{i['risk_score']},"
            f"{q(i['risk_factors'])}::jsonb,'open','none',{arr(i['mitre_techniques'])},NULL);")
    for iid, et, ev, role in inc_entities:
        L.append("insert into incident_entities (incident_id,entity_type,entity_value,role) "
                 f"values ({q(iid)},{q(et)},{q(ev)},{q(role)}) on conflict do nothing;")
    for e in events:
        vals = [q(e["event_id"]), q(e["ts"]), q(e["source_type"]), q(e["vendor"]), q(e["product"]),
                q(e["class_uid"]), q(e["category"]), q(e["activity"]), q(e["severity"]), q(e["outcome"]),
                q(e["src_ip"]), q(e["dst_ip"]), q(e["template_id"]), q(e["template_text"]),
                q(e["parser_confidence"]), arr(e["mitre_tags"]), q(e["raw"]), q(e["raw_hash"]),
                q(e["gt_label"]), q(e["gt_scenario"])]
        L.append(f"insert into events ({','.join(ECOLS)}) values ({','.join(vals)});")
    for s in signals:
        L.append("insert into signals (event_id,detector,detector_ref,score,reason) values "
                 f"({q(s['event_id'])},{q(s['detector'])},{q(s['detector_ref'])},{q(s['score'])},{q(s['reason'])});")
    for a in alerts:
        eids = "ARRAY[" + ",".join(q(x) for x in a["event_ids"]) + "]::uuid[]" if a["event_ids"] else "'{}'::uuid[]"
        L.append(
            "insert into alerts (alert_id,title,severity,confidence,detector,contributions,"
            "entity,event_ids,correlation_count,status,incident_id) values "
            f"({q(a['alert_id'])},{q(a['title'])},{q(a['severity'])},{a['confidence']},{q(a['detector'])},"
            f"{q(a['contributions'])}::jsonb,{q(a['entity'])},{eids},{a['correlation_count']},"
            f"{q(a['status'])},{q(a['incident_id'])});")
    for rid, title, det, tags, sev in RULES:
        L.append("insert into detection_rules (rule_id,title,detector,logic,mitre_tags,severity) values "
                 f"({q(rid)},{q(title)},{q(det)},{q(json.dumps({'ref': rid}))}::jsonb,{arr(tags)},{q(sev)}) "
                 "on conflict (rule_id) do nothing;")
    for tid, name, tac, desc in ATTACK_KB:
        L.append("insert into attack_kb (technique_id,name,tactic,description) values "
                 f"({q(tid)},{q(name)},{q(tac)},{q(desc)}) on conflict (technique_id) do nothing;")
    with open(SEED_SQL, "w") as f:
        f.write("\n".join(L) + "\ncommit;\n")


def prf(c):
    tp, fp, fn = c["tp"], c["fp"], c["fn"]
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return round(p, 4), round(r, 4), round(f1, 4)


def report(cm, events, signals):
    total = Counter()
    rows = {}
    for scen, c in cm.items():
        for k in ("tp", "fp", "fn", "tn"):
            total[k] += c[k]
        p, r, f1 = prf(c)
        rows[scen] = {"tp": c["tp"], "fp": c["fp"], "fn": c["fn"], "tn": c["tn"],
                      "precision": p, "recall": r, "f1": f1}
    p, r, f1 = prf(total)
    rows["overall"] = {"tp": total["tp"], "fp": total["fp"], "fn": total["fn"],
                       "tn": total["tn"], "precision": p, "recall": r, "f1": f1}
    with open(EVAL_JSON, "w") as f:
        json.dump({"note": "detectors evaluated on ALL CICIDS2017 flows for the 3 targeted "
                   "attack types; predicted-attack = >=1 behavioural signal fired",
                   "per_scenario": rows}, f, indent=2)
    print("\n=== detection evaluation (ALL flows, vs ground-truth Label) ===")
    print(f"{'scenario':<13}{'TP':>8}{'FP':>7}{'FN':>7}{'prec':>8}{'recall':>8}{'F1':>8}")
    for scen in ("brute_force", "ddos", "botnet", "overall"):
        m = rows[scen]
        print(f"{scen:<13}{m['tp']:>8}{m['fp']:>7}{m['fn']:>7}"
              f"{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>8.3f}")
    print(f"\nstored: events={len(events)} signals={len(signals)}")
    print(f"wrote {os.path.relpath(SEED_SQL)} and {os.path.relpath(EVAL_JSON)}")


if __name__ == "__main__":
    main()
