#!/usr/bin/env python3
"""
soccore.py  (AI-SOC) — shared detection core

Extracted from ingest_cicids.py so the SAME feature-based detectors, parsing,
and ATT&CK knowledge base drive BOTH:
  * the reproducible seed (ingest_cicids.py — fixed 3-file CICIDS demo), and
  * arbitrary uploaded files (analyze.py — one file, dynamic incident discovery).

Nothing here reads the ground-truth Label — the detectors are purely
behavioural. Stdlib only (no pandas/psycopg); the CSVs are 75-175 MB, streamed.
"""
import csv
import math
import re
import sys
import uuid
import statistics
from collections import defaultdict, Counter
from datetime import datetime, timezone

csv.field_size_limit(1 << 24)

# --- reproducible id namespace (shared so seed + uploads derive stable ids) ---
NS = uuid.UUID("5a0c0000-0000-0000-0000-000000000002")

# --- detector thresholds (behavioural; chosen from flow structure, not label) -
BF_PORTS = {"21", "22"}
BF_MIN_FLOWS = 30       # >=30 flows one src->dst on FTP/SSH == credential hammering
FLOOD_MIN_FLOWS = 3000  # >=3000 flows one src->dst:port == volumetric flood
FLOOD_EXCLUDE = {"53", "123"}  # DNS/NTP are legitimately high-volume — never a flood
BEACON_MIN_FLOWS = 20   # >=20 flows internal->same external dst == beaconing/C2
BEACON_MIN_FANIN = 3    # >=3 internal hosts fanning-in to one external dst == botnet C2
# ports whose external traffic is overwhelmingly benign infrastructure — excluded
# from the beacon detector so normal web/DNS/NTP browsing is not mistaken for C2.
COMMON_PORTS = {"80", "443", "53", "123", "8443"}

# --- storage sampling caps (keep the DB small + free-tier friendly) -----------
CAP_ATTACK = 700        # stored flows that fired >=1 signal, per scenario
CAP_BENIGN = 900        # stored no-signal flows, per scenario (context)

# --- MITRE technique mapping + titles -----------------------------------------
TECH = {"R-NET-BRUTEFORCE": "T1110", "R-NET-FLOOD": "T1498",
        "flow_rate_zscore": "T1498", "R-NET-BEACON": "T1071"}
SCEN_TECH = {"brute_force": ["T1110"], "ddos": ["T1498"], "botnet": ["T1071"]}
SCEN_TITLE = {"brute_force": "SSH/FTP brute-force credential attack",
              "ddos": "Volumetric HTTP DDoS flood",
              "botnet": "Ares botnet C2 beaconing"}

ECOLS = ["event_id", "ts", "source_type", "vendor", "product", "class_uid", "category",
         "activity", "severity", "outcome", "src_ip", "dst_ip", "template_id",
         "template_text", "parser_confidence", "mitre_tags", "raw", "raw_hash",
         "gt_label", "gt_scenario"]

RULES = [
    ("R-NET-BRUTEFORCE", "Network brute force (FTP/SSH)", "rule", ["T1110"], "high"),
    ("R-NET-FLOOD", "Volumetric flood / DDoS", "rule", ["T1498"], "high"),
    ("flow_rate_zscore", "Anomalous flow packet-rate", "statistical", ["T1498"], "medium"),
    ("R-NET-BEACON", "Botnet C2 beaconing", "ioc", ["T1071"], "high"),
]
ATTACK_KB = [
    ("T1110", "Brute Force", "Credential Access",
     "Adversaries systematically guess credentials via repeated authentication attempts, e.g. FTP/SSH password guessing (Patator, Hydra)."),
    ("T1498", "Network Denial of Service", "Impact",
     "Adversaries flood a target with traffic to exhaust bandwidth or resources, degrading availability (e.g. HTTP flood via LOIC)."),
    ("T1071", "Application Layer Protocol", "Command and Control",
     "Adversaries use common application-layer protocols (HTTP/HTTPS on ports like 8080) for C2 beaconing so traffic blends with normal activity."),
    ("T1499", "Endpoint Denial of Service", "Impact",
     "Adversaries exhaust the resources of a specific service or host to make it unavailable."),
    ("T1571", "Non-Standard Port", "Command and Control",
     "Adversaries use non-standard ports (e.g. 8080 for HTTP C2) to bypass filtering and blend in."),
    # --- techniques reachable via the Stage-1 attack-class bridge -------------
    ("T1190", "Exploit Public-Facing Application", "Initial Access",
     "Adversaries exploit a weakness in an internet-facing host or web application — SQL injection, Heartbleed, fuzzing and similar input-handling flaws — to gain initial access."),
    ("T1059", "Command and Scripting Interpreter", "Execution",
     "Adversaries abuse command and script interpreters to execute commands, including injection of operating-system or application commands via untrusted input."),
    ("T1059.007", "JavaScript (Cross-Site Scripting)", "Execution",
     "Adversaries inject malicious JavaScript that executes in a victim's browser session, as in reflected or stored cross-site scripting (XSS) against a web application."),
    ("T1046", "Network Service Discovery", "Discovery",
     "Adversaries enumerate hosts, open ports and running services — port scanning, probing and reconnaissance sweeps — to map the environment for later targeting."),
    ("T1078", "Valid Accounts", "Defense Evasion",
     "Adversaries use legitimate credentials or an established foothold to move within the environment, as in infiltration activity that blends with authorised access."),
    ("T1505", "Server Software Component", "Persistence",
     "Adversaries install a backdoor or malicious server component to retain persistent access to a compromised host."),
    ("T1203", "Exploitation for Client Execution", "Execution",
     "Adversaries exploit software vulnerabilities — shellcode, worms and generic memory-corruption exploits — to execute code on a target."),
    ("T1204", "User Execution", "Execution",
     "Adversaries rely on a user running a malicious file or link so that attacker-supplied code executes."),
    ("T1486", "Data Encrypted for Impact", "Impact",
     "Adversaries encrypt data on target systems to interrupt availability and extort the victim (ransomware)."),
    ("T1566", "Phishing", "Initial Access",
     "Adversaries send deceptive messages to induce a victim to reveal credentials or execute malicious content."),
    ("T1557", "Adversary-in-the-Middle", "Credential Access",
     "Adversaries position themselves between two communicating parties — via spoofing or traffic manipulation — to intercept or alter data in transit."),
]


# --- family metadata used by analyze.py's dynamic incident discovery ----------
# Priority orders single-owner assignment when one flow trips two families:
# credential access / C2 are more specific readings than raw volume, so a
# port-22 flow that fires BOTH brute-force and flood is owned by brute-force.
FAMILY_PRIORITY = {"brute_force": 0, "beacon": 1, "flood": 2}
FAMILY_TECH = {"brute_force": "T1110", "flood": "T1498", "beacon": "T1071"}
FAMILY_TITLE = {"brute_force": "SSH/FTP brute-force credential attack",
                "flood": "Volumetric network DDoS flood",
                "beacon": "Botnet C2 beaconing"}

# maps a detector_ref to the (family) it belongs to; flow_rate_zscore corroborates
# flood and folds into the same event's flood cluster.
DETECTOR_FAMILY = {"R-NET-BRUTEFORCE": "brute_force", "R-NET-FLOOD": "flood",
                   "flow_rate_zscore": "flood", "R-NET-BEACON": "beacon"}


# =============================================================================
# STAGE-1 ATTACK-CLASS BRIDGE  (how arbitrary datasets reach the agent layer)
#
# The four behavioural detectors above only recognise three flow shapes
# (credential hammering, volumetric flood, beacon fan-in). A dataset whose
# attack is an HTTP *payload* attack — SQL injection, XSS, a port scan — is
# parsed perfectly but fires NOTHING, so no incident is created and the agent
# layer is never reached.
#
# This bridge closes that gap WITHOUT pretending to detect those attacks: when
# the dataset carries its own ground-truth attack column, each non-benign class
# becomes a signal of detector type "label" with an explicitly annotated reason.
# It is an ANNOTATION, not an independent detection, and is scored/labelled as
# such everywhere downstream so the distinction survives into the UI and report:
#
#   behavioural detector fired  -> independent evidence   (score 0.60-0.97)
#   dataset label only          -> annotation             (score LABEL_SCORE)
#
# Stage 3 (the verifier) reports whether each labelled attack was CORROBORATED
# by an independent detector or is annotation-only. That corroboration rate is
# an honest, measurable result rather than a laundered confidence number.
# =============================================================================

# Score carried by an annotation-derived signal. Deliberately mid-range: the
# annotation is reliable ABOUT ITSELF but is not independent detection evidence.
LABEL_SCORE = 0.5

# Labels that mean "no attack". Matched case-insensitively after whitespace
# collapse, against the whole value.
BENIGN_LABELS = {"benign", "normal", "background", "none", "no", "clean",
                 "legitimate", "non-tor", "0", "-", ""}

# Ordered (substring, canonical attack class, ATT&CK technique). FIRST match
# wins, so more specific patterns MUST precede the substrings they contain
# ("ddos" before "dos", "botnet" before "bot", "portscan" before "scan",
# "sql injection" before "injection").
ATTACK_SIGNATURES = [
    ("sql injection", "SQL Injection", "T1190"),
    ("sqli", "SQL Injection", "T1190"),
    ("cross site scripting", "Cross-Site Scripting", "T1059.007"),
    ("cross-site scripting", "Cross-Site Scripting", "T1059.007"),
    ("xss", "Cross-Site Scripting", "T1059.007"),
    ("heartbleed", "Heartbleed Exploitation", "T1190"),
    ("ftp-patator", "Brute Force", "T1110"),
    ("ssh-patator", "Brute Force", "T1110"),
    ("patator", "Brute Force", "T1110"),
    ("brute force", "Brute Force", "T1110"),
    ("bruteforce", "Brute Force", "T1110"),
    ("brute-force", "Brute Force", "T1110"),
    ("password", "Brute Force", "T1110"),
    ("credential", "Brute Force", "T1110"),
    ("ddos", "Network Denial of Service", "T1498"),
    ("slowhttptest", "Endpoint Denial of Service", "T1499"),
    ("slowloris", "Endpoint Denial of Service", "T1499"),
    ("goldeneye", "Endpoint Denial of Service", "T1499"),
    ("hulk", "Endpoint Denial of Service", "T1499"),
    ("dos", "Endpoint Denial of Service", "T1499"),
    ("flood", "Network Denial of Service", "T1498"),
    ("botnet", "Botnet C2 Beaconing", "T1071"),
    ("bot", "Botnet C2 Beaconing", "T1071"),
    ("beacon", "Botnet C2 Beaconing", "T1071"),
    ("portscan", "Network Service Discovery", "T1046"),
    ("port scan", "Network Service Discovery", "T1046"),
    ("reconnaissance", "Network Service Discovery", "T1046"),
    ("scan", "Network Service Discovery", "T1046"),
    ("probe", "Network Service Discovery", "T1046"),
    ("infiltration", "Infiltration via Valid Access", "T1078"),
    ("backdoor", "Backdoor Implant", "T1505"),
    ("shellcode", "Exploitation for Client Execution", "T1203"),
    ("worm", "Exploitation for Client Execution", "T1203"),
    ("exploit", "Exploitation for Client Execution", "T1203"),
    ("fuzzers", "Application Fuzzing", "T1190"),
    ("web attack", "Web Application Attack", "T1190"),
    ("injection", "Command Injection", "T1059"),
    ("ransomware", "Data Encrypted for Impact", "T1486"),
    ("phishing", "Phishing", "T1566"),
    ("spoof", "Adversary-in-the-Middle", "T1557"),
    ("mitm", "Adversary-in-the-Middle", "T1557"),
    ("analysis", "Network Service Discovery", "T1046"),
    ("generic", "Unclassified Malicious Activity", "T1203"),
]

# A non-benign label matching no signature still becomes an incident — the
# agents can reason about it from evidence — but is named honestly.
UNKNOWN_ATTACK = ("Unclassified Malicious Activity", "T1203")

LABEL_FAMILY_PREFIX = "labelled:"
# Annotation-derived families rank BELOW every behavioural family, so when a row
# fires both a real detector and a label, the behavioural reading owns the event
# (see assign_owner) and the label never displaces independent evidence.
LABEL_FAMILY_PRIORITY = 9


def normalize_label(raw) -> str:
    """Collapse a raw label cell to a comparable lowercase token."""
    return " ".join(str(raw or "").strip().lower().replace("_", " ").split())


def is_benign_label(raw) -> bool:
    return normalize_label(raw) in BENIGN_LABELS


def label_detector_ref(attack_class: str) -> str:
    slug = re.sub(r"[^A-Z0-9]+", "-", attack_class.upper()).strip("-")
    return f"LBL-{slug}"


def classify_attack_label(raw):
    """Map a dataset's raw attack label to a canonical class + ATT&CK technique.

    Returns None for benign/empty labels. Otherwise returns a dict and registers
    the derived detector_ref in TECH / DETECTOR_FAMILY / FAMILY_* so the rest of
    the pipeline (mitre tagging, ownership, titling) treats it like any family.
    """
    norm = normalize_label(raw)
    if norm in BENIGN_LABELS:
        return None
    attack_class, technique = UNKNOWN_ATTACK
    for needle, cls, tech in ATTACK_SIGNATURES:
        if needle in norm:
            attack_class, technique = cls, tech
            break
    ref = label_detector_ref(attack_class)
    family = LABEL_FAMILY_PREFIX + attack_class
    # Register so TECH[ref], family_of(ref) and FAMILY_* lookups all resolve.
    TECH.setdefault(ref, technique)
    DETECTOR_FAMILY.setdefault(ref, family)
    FAMILY_PRIORITY.setdefault(family, LABEL_FAMILY_PRIORITY)
    FAMILY_TECH.setdefault(family, technique)
    FAMILY_TITLE.setdefault(family, attack_class)
    return {"attack_class": attack_class, "technique": technique,
            "detector_ref": ref, "family": family, "raw_label": str(raw or "").strip()}


def label_rule_rows():
    """detection_rules rows for every annotation-derived ref registered so far.
    Keeps the rules table (and the Overview rule count) consistent with the
    signals actually written, and records that these are annotation-sourced."""
    rows = []
    for ref, family in DETECTOR_FAMILY.items():
        if not family.startswith(LABEL_FAMILY_PREFIX):
            continue
        cls = family[len(LABEL_FAMILY_PREFIX):]
        rows.append((ref, f"Dataset-annotated attack class: {cls}", "label",
                     [TECH.get(ref, "")], "high"))
    return rows



# --- parsing helpers ----------------------------------------------------------
def is_internal(ip: str) -> bool:
    return ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("10.")


# Common CICFlowMeter/CICIDS column variants. The detector continues to use one
# canonical internal schema; only the header lookup is made more tolerant.
HEADER_ALIASES = {
    "flow id": "Flow ID", "flowid": "Flow ID",
    "source ip": "Source IP", "src ip": "Source IP", "srcip": "Source IP", "src addr": "Source IP",
    "destination ip": "Destination IP", "dst ip": "Destination IP", "dstip": "Destination IP", "dest ip": "Destination IP", "dst addr": "Destination IP",
    "source port": "Source Port", "src port": "Source Port", "sport": "Source Port",
    "destination port": "Destination Port", "dst port": "Destination Port", "dest port": "Destination Port", "dsport": "Destination Port",
    "timestamp": "Timestamp", "time stamp": "Timestamp", "flow start time": "Timestamp", "start time": "Timestamp", "stime": "Timestamp",
    "protocol": "Protocol", "proto": "Protocol",
    "flow packets/s": "Flow Packets/s", "flow pkts/s": "Flow Packets/s", "flow packets s": "Flow Packets/s",
    "total fwd packets": "Total Fwd Packets", "tot fwd pkts": "Total Fwd Packets",
    "total backward packets": "Total Backward Packets", "total bwd packets": "Total Backward Packets", "tot bwd pkts": "Total Backward Packets",
    "flow duration": "Flow Duration",
    # --- ground-truth / attack-class column, across dataset families ----------
    # CICIDS/CSE-CIC use "Label"; UNSW-NB15 uses "attack_cat"; NSL-KDD uses
    # "class"; misc exports use "attack_type"/"category". All normalize to Label.
    # First match wins (idx.setdefault), so a dataset carrying both keeps the
    # left-most column — documented, deliberate.
    "label": "Label", "labels": "Label", "attack cat": "Label",
    "attack category": "Label", "attack type": "Label", "attack": "Label",
    "class": "Label", "category": "Label", "traffic type": "Label",
}


def _header_key(s: str) -> str:
    return " ".join(s.strip().lower().replace("_", " ").replace("-", " ").split())


def parse_ts(s: str):
    """Parse common CICIDS/CICFlowMeter timestamps plus ISO/epoch variants."""
    s = str(s or "").strip()
    if not s:
        return None
    # Unix seconds / milliseconds (common in exported flow datasets).
    try:
        x = float(s)
        if x > 1_000_000_000_000:
            x /= 1000.0
        if x > 100_000_000:
            return datetime.fromtimestamp(x, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError):
        pass
    # ISO-8601 first.
    try:
        iso = s[:-1] + "+00:00" if s.endswith("Z") else s
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        pass
    # CICIDS/CICFlowMeter and common CSV exports.
    for fmt in (
        "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %I:%M %p", "%d/%m/%Y %H:%M",
        "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M %p", "%m/%d/%Y %H:%M",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def open_rows(path):
    """Return CSV reader + an alias-aware canonical header index."""
    f = open(path, "r", encoding="latin-1", newline="")
    reader = csv.reader(f)
    header = [h.strip() for h in next(reader)]
    idx = {}
    for i, name in enumerate(header):
        idx.setdefault(name, i)
        canonical = HEADER_ALIASES.get(_header_key(name))
        if canonical:
            idx.setdefault(canonical, i)
    return f, reader, idx


def g(row, idx, name):
    i = idx.get(name)
    if i is None or i >= len(row):
        return ""
    return row[i].strip()


def fnum(v):
    try:
        x = float(v)
        return x if math.isfinite(x) else 0.0
    except (ValueError, TypeError):
        return 0.0
# PLACEHOLDER_DETECT


# --- detectors (feature-based; identical logic for seed + uploads) ------------
def detect(row, idx, aggs, scen):
    """Return list of signal dicts. Reads flow FEATURES only — never the Label."""
    out = []
    src = g(row, idx, "Source IP"); dst = g(row, idx, "Destination IP")
    dport = g(row, idx, "Destination Port")
    # R-NET-BRUTEFORCE (T1110)
    if dport in BF_PORTS:
        n = aggs["bf"][(scen, src, dst, dport)]
        if n >= BF_MIN_FLOWS:
            svc = "FTP" if dport == "21" else "SSH"
            score = min(0.95, 0.6 + math.log10(n) / 8)
            out.append(dict(detector="rule", detector_ref="R-NET-BRUTEFORCE", score=round(score, 3),
                            reason=f"{n} {svc} connection attempts {src} -> {dst}:{dport}"))
    # R-NET-FLOOD (T1498) + statistical packet-rate corroboration
    n = aggs["flood"][(scen, src, dst, dport)]
    if dport not in FLOOD_EXCLUDE and n >= FLOOD_MIN_FLOWS:
        score = min(0.97, 0.7 + math.log10(n) / 10)
        out.append(dict(detector="rule", detector_ref="R-NET-FLOOD", score=round(score, 3),
                        reason=f"volumetric flood: {n} flows {src} -> {dst}:{dport}"))
        rate = fnum(g(row, idx, "Flow Packets/s"))
        z = (rate - aggs["rate_mean"]) / aggs["rate_sd"]
        if z > 3:
            out.append(dict(detector="statistical", detector_ref="flow_rate_zscore",
                            score=round(min(0.9, 0.4 + z / 40), 3),
                            reason=f"flow packet-rate z-score {z:.1f}"))
    # R-NET-BEACON (T1071) botnet C2 — repeated internal->external flows on a
    # non-web port, with several internal hosts fanning-in to the same destination.
    if is_internal(src) and dst and not is_internal(dst) and dport not in COMMON_PORTS:
        n = aggs["beacon"][(scen, src, dst)]
        fanin = len(aggs["beacon_srcs"][(scen, dst)])
        if n >= BEACON_MIN_FLOWS and fanin >= BEACON_MIN_FANIN:
            score = 0.75 + min(0.2, fanin / 50)
            out.append(dict(detector="ioc", detector_ref="R-NET-BEACON", score=round(score, 3),
                            reason=f"{n} repeated flows {src} -> external {dst}:{dport} "
                                   f"(beaconing); {fanin} internal hosts fan-in to this C2"))
    return out


# --- pass 1: behavioural aggregates -------------------------------------------
def build_aggregates(sources):
    """Build per-scenario behavioural aggregates over one or more CSVs.

    sources = list of (csv_path, scen). Keying by scen keeps temporally separate
    captures from bleeding together (the seed passes 3 files; analyze.py passes
    one file under a single implicit scen)."""
    bf = Counter()            # (scen,src,dst,dport in 21/22) -> flow count
    flood = Counter()         # (scen,src,dst,dport) -> flow count
    beacon = Counter()        # (scen,src,ext_dst) -> flow count  (internal src only)
    beacon_srcs = defaultdict(set)  # (scen,ext_dst) -> set of internal srcs (fan-in)
    beacon_total = Counter()  # (scen,ext_dst) -> total beacon flows (all srcs)
    rates = []                # sample of Flow Packets/s for a z-score baseline
    benign = Counter()        # scenario -> benign flow count (for sampling stride)
    for path, scen in sources:
        f, reader, idx = open_rows(path)
        _n = 0
        for row in reader:
            # Progress to stderr (stdout carries the JSON result). The backend
            # streams these lines to its console so a 90 MB file visibly
            # advances instead of looking hung.
            _n += 1
            if _n % 50000 == 0:
                print(f"pass 1/2 (aggregate): {_n:,} rows", file=sys.stderr, flush=True)
            if len(row) < 4:
                continue
            src = g(row, idx, "Source IP"); dst = g(row, idx, "Destination IP")
            dport = g(row, idx, "Destination Port")
            if not src or not dst:
                continue
            if is_benign_label(g(row, idx, "Label")):
                benign[scen] += 1
            flood[(scen, src, dst, dport)] += 1
            if dport in BF_PORTS:
                bf[(scen, src, dst, dport)] += 1
            if is_internal(src) and dst and not is_internal(dst) and dport not in COMMON_PORTS:
                beacon[(scen, src, dst)] += 1
                beacon_srcs[(scen, dst)].add(src)
                beacon_total[(scen, dst)] += 1
            r = fnum(g(row, idx, "Flow Packets/s"))
            if r > 0 and len(rates) < 200000:
                rates.append(r)
        f.close()
    mean = statistics.mean(rates) if rates else 0.0
    sd = statistics.pstdev(rates) if len(rates) > 1 else 1.0
    return {"bf": bf, "flood": flood, "beacon": beacon,
            "beacon_srcs": beacon_srcs, "beacon_total": beacon_total,
            "rate_mean": mean, "rate_sd": sd or 1.0, "benign": benign}


# --- SQL + formatting helpers (used by ingest_cicids.py's SQL emitter) --------
def q(v):
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def arr(vals):
    if not vals:
        return "'{}'::text[]"
    return "ARRAY[" + ",".join(q(v) for v in vals) + "]::text[]"


def sev_band(score):
    return ("high" if score >= 0.85 else "medium" if score >= 0.60
            else "low" if score >= 0.35 else "info")


def family_of(detector_ref):
    """The attack family a detector_ref belongs to (None if unknown)."""
    return DETECTOR_FAMILY.get(detector_ref)


def cluster_key(family, src, dst, dport):
    """The clustering key for a signal's family:
       brute_force -> (src, dst)   flood -> (dst, dport)   beacon -> (dst,)
       labelled:<class> -> (dst,)  — one incident per attack class per target,
       since the class is already encoded in the family name."""
    if family == "brute_force":
        return (src, dst)
    if family == "flood":
        return (dst, dport)
    if family == "beacon":
        return (dst,)
    if family and family.startswith(LABEL_FAMILY_PREFIX):
        return (dst,)
    return None
