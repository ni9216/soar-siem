"""
Advanced Log Correlation Engine
---------------------------------
Detects multi-step attack chains by tracking events per source IP
over a sliding time window.
"""

import re
import time
from collections import defaultdict, deque
from datetime import datetime

_WINDOW_SECONDS = 300
_event_store: dict = defaultdict(lambda: deque(maxlen=100))

ATTACK_CHAINS = [
    {"name": "Reconnaissance → Exploitation → Exfiltration", "severity": "Critical",
     "steps": ["reconnaissance", "exploitation", "exfiltration"], "mitre": "T1595 → T1190 → T1041"},
    {"name": "Brute Force → Privilege Escalation", "severity": "Critical",
     "steps": ["brute_force", "privilege_escalation"], "mitre": "T1110 → T1068"},
    {"name": "Port Scan → Exploit Attempt", "severity": "High",
     "steps": ["port_scan", "exploitation"], "mitre": "T1046 → T1190"},
    {"name": "Malware → C2 → Lateral Movement", "severity": "Critical",
     "steps": ["malware", "c2_communication", "lateral_movement"], "mitre": "T1059 → T1071 → T1021"},
    {"name": "Ransomware Chain", "severity": "Critical",
     "steps": ["malware", "file_encryption"], "mitre": "T1059 → T1486"},
    {"name": "DDoS Pattern", "severity": "High",
     "steps": ["flood", "flood", "flood"], "mitre": "T1498"},
]

EVENT_PATTERNS = {
    "reconnaissance":     ["scan", "probe", "enumerate", "fingerprint", "nmap", "masscan"],
    "brute_force":        ["brute", "multiple failed", "repeated login", "password spray"],
    "exploitation":       ["exploit", "payload", "shellcode", "overflow", "injection", "rce"],
    "exfiltration":       ["exfil", "data transfer", "outbound data", "sent to external"],
    "privilege_escalation": ["privilege", "sudo", "root escalat", "elevation"],
    "lateral_movement":   ["lateral", "pivot", "rdp", "psexec", "wmi", "remote exec"],
    "malware":            ["malware", "trojan", "backdoor", "rootkit", "virus", "worm"],
    "c2_communication":   ["c2", "command and control", "beacon", "callback", "reverse shell"],
    "file_encryption":    ["encrypt", "ransom", "locked", ".enc", "crypted"],
    "flood":              ["flood", "ddos", "dos", "high volume", "traffic spike"],
    "port_scan":          ["port scan", "scanning ports", "open port"],
}


def classify_event(log: str) -> list:
    t = log.lower()
    return [etype for etype, kws in EVENT_PATTERNS.items() if any(kw in t for kw in kws)]


def extract_source_ip(log: str):
    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', log)
    return ips[0] if ips else None


def record_event(log: str):
    ip = extract_source_ip(log) or "unknown"
    now = time.time()
    for etype in classify_event(log):
        _event_store[ip].append((now, etype))


def _recent(ip: str) -> list:
    cutoff = time.time() - _WINDOW_SECONDS
    return [e for ts, e in _event_store.get(ip, []) if ts >= cutoff]


def check_attack_chains(log: str) -> list:
    record_event(log)
    ip = extract_source_ip(log) or "unknown"
    recent = _recent(ip)
    detected = []
    for chain in ATTACK_CHAINS:
        steps, idx = chain["steps"], 0
        for event in recent:
            if event == steps[idx]:
                idx += 1
            if idx == len(steps):
                detected.append({"chain": chain["name"], "severity": chain["severity"],
                                  "mitre": chain["mitre"], "source_ip": ip,
                                  "detected_at": datetime.utcnow().isoformat()})
                break
    return detected


def correlate(log: str) -> str:
    t = log.lower()
    if "scan" in t and "failed login" in t:
        return "Possible Intrusion Attempt"
    if "ransomware" in t and "file encrypted" in t:
        return "Ransomware Attack"
    if "malware" in t and "outbound connection" in t:
        return "Malware Communication"
    chains = check_attack_chains(log)
    return chains[0]["chain"] if chains else "Generic Security Event"


def get_ip_timeline(ip: str) -> list:
    return [{"timestamp": datetime.utcfromtimestamp(ts).isoformat(), "event": e}
            for ts, e in _event_store.get(ip, [])]


def get_all_suspicious_ips() -> list:
    cutoff = time.time() - _WINDOW_SECONDS
    result = []
    for ip, events in _event_store.items():
        recent = [e for ts, e in events if ts >= cutoff]
        if len(recent) >= 3:
            result.append({"ip": ip, "event_count": len(recent), "events": list(set(recent))})
    return sorted(result, key=lambda x: x["event_count"], reverse=True)

