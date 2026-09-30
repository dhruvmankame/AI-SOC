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
    "label": "Label",
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
        for row in reader:
            if len(row) < 4:
                continue
            src = g(row, idx, "Source IP"); dst = g(row, idx, "Destination IP")
            dport = g(row, idx, "Destination Port")
            if not src or not dst:
                continue
            if g(row, idx, "Label").upper() == "BENIGN":
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
       brute_force -> (src, dst)   flood -> (dst, dport)   beacon -> (dst,)."""
    if family == "brute_force":
        return (src, dst)
    if family == "flood":
        return (dst, dport)
    if family == "beacon":
        return (dst,)
    return None
