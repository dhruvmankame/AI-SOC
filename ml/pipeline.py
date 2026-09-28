#!/usr/bin/env python3
"""
pipeline.py  (AI-SOC, Day 1)

Offline detection-plane pipeline (stdlib only, runs anywhere):

  raw_events.jsonl
    -> template mining      (Drain-lite; swap in drain3 later)
    -> OCSF-subset normalize (§10.1)
    -> rule + statistical detectors (§9.1)  -> signals
    -> seed export           (data/seed.sql + data/seed.json)

The seed loads straight into the Supabase schema (supabase/migrations/0001_init.sql)
and also feeds the frontend during early development before the live API exists.
"""
import json, os, re, statistics
from collections import defaultdict, Counter

HERE = os.path.dirname(__file__)
RAW  = os.path.join(HERE, "..", "data", "raw_events.jsonl")
SEED_SQL  = os.path.join(HERE, "..", "data", "seed.sql")
SEED_JSON = os.path.join(HERE, "..", "data", "seed.json")

IP_RE   = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
NUM_RE  = re.compile(r"\b\d+\b")
HEX_RE  = re.compile(r"\b[0-9a-fA-F]{8,}\b")

# ------------------------------------------------------- template mining (Drain-lite)
def mine_template(msg: str):
    """Replace volatile tokens with <*> to derive a stable template id."""
    t = HEX_RE.sub("<*>", msg)
    t = IP_RE.sub("<ip>", t)
    t = NUM_RE.sub("<*>", t)
    t = re.sub(r"\s+", " ", t).strip()
    tid = "T" + str(abs(hash(t)) % 100000)
    return tid, t

# ------------------------------------------------------- source-specific parsers
AUTH_RE = re.compile(r"(Accepted|Failed) password for (\S+) from (\d{1,3}(?:\.\d{1,3}){3})")
SUDO_RE = re.compile(r"sudo:\s+(\S+)\s+:.*USER=(\S+)\s+;\s+COMMAND=(\S+)")
WEB_RE  = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}).*"(\w+)\s+(\S+)\s+HTTP.*"\s+(\d{3})')
FW_RE   = re.compile(r"fw:\s+(\w+)\s+src=(\S+)\s+dst=(\S+)\s+proto=(\w+)\s+dport=(\d+)")

def normalize(rec: dict) -> dict:
    """Map a raw record to the OCSF-subset event model."""
    st, raw = rec["source_type"], rec["raw"]
    tid, ttext = mine_template(raw)
    e = {
        "ts": rec["ts"], "source_type": st, "raw": raw, "raw_hash": rec["raw_hash"],
        "template_id": tid, "template_text": ttext, "parser_confidence": 0.9,
        "severity": "info", "outcome": "unknown",
        "user": None, "host": None, "src_ip": None, "dst_ip": None,
        "domain": None, "process": None, "file_hash": None,
        "category": st, "activity": None, "class_uid": None,
        "gt_label": rec.get("gt_label"), "gt_scenario": rec.get("gt_scenario"),
    }
    if st == "auth":
        m = AUTH_RE.search(raw)
        if m:
            e["activity"] = "authentication"; e["class_uid"] = 3002
            e["outcome"] = "success" if m.group(1) == "Accepted" else "failure"
            e["user"] = m.group(2); e["src_ip"] = m.group(3)
            e["severity"] = "low" if e["outcome"] == "failure" else "info"
        m2 = SUDO_RE.search(raw)
        if m2:
            e["activity"] = "privilege_use"; e["class_uid"] = 3005
            e["user"] = m2.group(1); e["outcome"] = "success"; e["severity"] = "medium"
        host_m = re.search(r"\b(WS-\d+|SRV-\w+|DC-\d+)\b", raw)
        if host_m: e["host"] = host_m.group(1)
    elif st in ("process", "network"):
        try:
            j = json.loads(raw)
            e["host"] = j.get("host"); e["user"] = j.get("user")
            e["process"] = j.get("process"); e["activity"] = j.get("event")
            e["dst_ip"] = j.get("dst_ip"); e["domain"] = j.get("domain")
            e["class_uid"] = 1007 if st == "process" else 4001
        except json.JSONDecodeError:
            pass
    elif st == "web":
        m = WEB_RE.search(raw)
        if m:
            e["src_ip"] = m.group(1); e["activity"] = m.group(2)
            e["outcome"] = "success" if m.group(4).startswith("2") else "failure"
            e["class_uid"] = 6003
    elif st == "firewall":
        m = FW_RE.search(raw)
        if m:
            e["activity"] = m.group(1).lower()
            e["src_ip"] = m.group(2) if IP_RE.match(m.group(2)) else None
            e["dst_ip"] = m.group(3) if IP_RE.match(m.group(3)) else None
            e["class_uid"] = 4001
    return e

# ------------------------------------------------------- detectors (§9.1)
BAD_IPS   = {"203.0.113.66"}
RARE_DOMS = {"cdn-update-sync.example.net"}

def detect(events):
    """Return list of signal dicts referencing event uuids."""
    signals = []
    # --- statistical: failed-login volume per src_ip ---
    fails = Counter(e["src_ip"] for e in events
                    if e["source_type"] == "auth" and e["outcome"] == "failure" and e["src_ip"])
    counts = list(fails.values()) or [0]
    mean = statistics.mean(counts); sd = statistics.pstdev(counts) or 1.0
    spray_ips = {ip for ip, c in fails.items() if c >= 8}

    for e in events:
        eid, st = e["_id"], e["source_type"]
        # R-AUTH-BRUTEFORCE + statistical z-score
        if st == "auth" and e["outcome"] == "failure" and e["src_ip"] in spray_ips:
            z = (fails[e["src_ip"]] - mean) / sd
            signals.append(dict(event_id=eid, detector="rule", detector_ref="R-AUTH-BRUTEFORCE",
                                score=0.7, reason=f"{fails[e['src_ip']]} failed logins from {e['src_ip']}"))
            signals.append(dict(event_id=eid, detector="statistical", detector_ref="failed_login_zscore",
                                score=min(0.99, 0.4 + 0.1 * z), reason=f"z-score {z:.1f} on failed-login rate"))
        # R-AUTH-SUCCESS-AFTER-FAIL
        if st == "auth" and e["outcome"] == "success" and e["src_ip"] in spray_ips:
            signals.append(dict(event_id=eid, detector="rule", detector_ref="R-SUCCESS-AFTER-SPRAY",
                                score=0.9, reason=f"successful login from spraying ip {e['src_ip']}"))
        # R-PRIV-ESC
        if e["activity"] == "privilege_use":
            signals.append(dict(event_id=eid, detector="rule", detector_ref="R-PRIV-ESCALATION",
                                score=0.75, reason="privilege escalation (sudo to root)"))
        # R-SUSPICIOUS-PROC
        if st == "process" and e["process"] == "powershell.exe" and ("-enc" in e["raw"] or "winword" in e["raw"]):
            signals.append(dict(event_id=eid, detector="rule", detector_ref="R-SUSPICIOUS-PROC",
                                score=0.8, reason="encoded powershell spawned by office parent"))
        # R-C2-BEACON  (rule + IOC)
        if (e["dst_ip"] in BAD_IPS) or (e["domain"] in RARE_DOMS):
            signals.append(dict(event_id=eid, detector="ioc", detector_ref="ioc:known_bad",
                                score=0.85, reason=f"outbound to known-bad {e['dst_ip'] or e['domain']}"))
        # R-PROMPT-INJECTION (content flag; the point is it is DATA, not an instruction)
        if st == "web" and re.search(r"ignore.*previous.*instruction", e["raw"], re.I):
            signals.append(dict(event_id=eid, detector="rule", detector_ref="R-PROMPT-INJECTION",
                                score=0.6, reason="prompt-injection pattern in log text (treated as untrusted)"))
    return signals

# ------------------------------------------------------- seed export
import uuid
NS = uuid.UUID("5a0c0000-0000-0000-0000-000000000001")  # fixed namespace -> reproducible ids

def q(v):
    if v is None: return "NULL"
    if isinstance(v, (int, float)): return str(v)
    return "'" + str(v).replace("'", "''") + "'"

RULES = [
    ("R-AUTH-BRUTEFORCE","Brute force / password spray","rule",["T1110"],"high"),
    ("R-SUCCESS-AFTER-SPRAY","Successful login after spray","rule",["T1078"],"high"),
    ("R-PRIV-ESCALATION","Privilege escalation","rule",["T1548"],"high"),
    ("R-SUSPICIOUS-PROC","Suspicious process execution","rule",["T1059"],"high"),
    ("R-C2-BEACON","C2 / rare outbound","ioc",["T1071"],"high"),
    ("R-PROMPT-INJECTION","Prompt injection in telemetry","rule",["T1566"],"medium"),
]
ATTACK_KB = [
    ("T1110","Brute Force","Credential Access","Adversaries guess passwords via repeated attempts."),
    ("T1078","Valid Accounts","Defense Evasion","Use of legitimate credentials for access."),
    ("T1548","Abuse Elevation Control","Privilege Escalation","Bypass mechanisms to elevate privileges."),
    ("T1059","Command and Scripting Interpreter","Execution","Abuse of command/script interpreters."),
    ("T1071","Application Layer Protocol","Command and Control","C2 over common protocols like HTTPS."),
    ("T1566","Phishing","Initial Access","Malicious content delivered to users."),
]

def main():
    with open(RAW) as f:
        raw = [json.loads(l) for l in f]
    events = [normalize(r) for r in raw]
    for e in events:
        e["_id"] = str(uuid.uuid5(NS, e["raw_hash"] + e["ts"]))
    signals = detect(events)

    ecols = ["event_id","ts","source_type","class_uid","category","activity","severity","outcome",
             "\"user\"","host","src_ip","dst_ip","domain","process","template_id","template_text",
             "parser_confidence","raw","raw_hash","gt_label","gt_scenario"]
    lines = ["-- generated by ml/pipeline.py", "truncate signals, events cascade;"]
    for e in events:
        vals = [q(e["_id"]),q(e["ts"]),q(e["source_type"]),q(e["class_uid"]),q(e["category"]),
                q(e["activity"]),q(e["severity"]),q(e["outcome"]),q(e["user"]),q(e["host"]),
                q(e["src_ip"]),q(e["dst_ip"]),q(e["domain"]),q(e["process"]),q(e["template_id"]),
                q(e["template_text"]),q(e["parser_confidence"]),q(e["raw"]),q(e["raw_hash"]),
                q(e["gt_label"]),q(e["gt_scenario"])]
        lines.append(f"insert into events ({','.join(ecols)}) values ({','.join(vals)});")
    for s in signals:
        lines.append("insert into signals (event_id,detector,detector_ref,score,reason) values "
                     f"({q(s['event_id'])},{q(s['detector'])},{q(s['detector_ref'])},{q(s['score'])},{q(s['reason'])});")
    for rid,title,det,tags,sev in RULES:
        logic = q(json.dumps({"ref": rid}))
        tagsql = "ARRAY[" + ",".join(q(t) for t in tags) + "]::text[]"
        lines.append(f"insert into detection_rules (rule_id,title,detector,logic,mitre_tags,severity) "
                     f"values ({q(rid)},{q(title)},{q(det)},{logic}::jsonb,{tagsql},{q(sev)}) on conflict do nothing;")
    for tid,name,tac,desc in ATTACK_KB:
        lines.append(f"insert into attack_kb (technique_id,name,tactic,description) "
                     f"values ({q(tid)},{q(name)},{q(tac)},{q(desc)}) on conflict do nothing;")

    with open(SEED_SQL, "w") as f: f.write("\n".join(lines) + "\n")
    with open(SEED_JSON, "w") as f:
        json.dump({"events": [{k: v for k, v in e.items()} for e in events],
                   "signals": signals}, f, indent=1, default=str)

    print(f"events={len(events)} signals={len(signals)} "
          f"attack_events={sum(1 for e in events if e['gt_label']=='attack')}")
    print(f"wrote {os.path.relpath(SEED_SQL)} and {os.path.relpath(SEED_JSON)}")

if __name__ == "__main__":
    main()
