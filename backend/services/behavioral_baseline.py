"""
Behavioral Baseline Service
-----------------------------
Learns normal activity patterns per user/IP over time.
Alerts when behavior deviates from the baseline.
"""

import time
import math
from collections import defaultdict
from datetime import datetime

# Baseline: {key -> {"count": int, "hours": Counter, "last_seen": ts}}
_baseline: dict = defaultdict(lambda: {
    "total": 0, "hours": defaultdict(int),
    "days": defaultdict(int), "ips": defaultdict(int),
    "first_seen": None, "last_seen": None,
})

# Recent activity for deviation detection (last 1 hour)
_recent: dict = defaultdict(list)
_RECENT_WINDOW = 3600   # 1 hour


def record_activity(user: str, ip: str = None, action: str = "login"):
    """Record an activity event for a user."""
    now = time.time()
    dt = datetime.utcfromtimestamp(now)
    key = user

    b = _baseline[key]
    b["total"] += 1
    b["hours"][dt.hour] += 1
    b["days"][dt.weekday()] += 1
    if ip:
        b["ips"][ip] += 1
    if b["first_seen"] is None:
        b["first_seen"] = now
    b["last_seen"] = now

    _recent[key].append({"ts": now, "ip": ip, "action": action, "hour": dt.hour})
    # Trim old recent events
    cutoff = now - _RECENT_WINDOW
    _recent[key] = [e for e in _recent[key] if e["ts"] >= cutoff]


def analyze_deviation(user: str, ip: str = None) -> dict:
    """
    Analyze if current activity deviates from the user's baseline.
    Returns: {"anomalous": bool, "reasons": [...], "risk_score": 0-100}
    """
    b = _baseline.get(user)
    reasons = []
    risk = 0

    if not b or b["total"] < 10:
        return {"anomalous": False, "reasons": ["Insufficient baseline data"], "risk_score": 0}

    now = time.time()
    dt = datetime.utcnow()

    # 1. Unusual hour
    usual_hours = {h for h, cnt in b["hours"].items() if cnt >= 2}
    if usual_hours and dt.hour not in usual_hours:
        reasons.append(f"Login at unusual hour: {dt.hour}:00")
        risk += 25

    # 2. New IP address
    if ip and ip not in b["ips"]:
        reasons.append(f"Login from new IP: {ip}")
        risk += 30

    # 3. High frequency (more than 3x average in last hour)
    recent_count = len(_recent.get(user, []))
    avg_hourly = b["total"] / max(1, (now - b["first_seen"]) / 3600)
    if recent_count > avg_hourly * 3 and avg_hourly > 1:
        reasons.append(f"Unusually high activity: {recent_count} events vs avg {avg_hourly:.1f}/hr")
        risk += 35

    # 4. Multiple IPs in short window
    recent_ips = {e["ip"] for e in _recent.get(user, []) if e["ip"]}
    if len(recent_ips) > 3:
        reasons.append(f"Accessing from {len(recent_ips)} different IPs in last hour")
        risk += 40

    risk = min(risk, 100)
    return {
        "anomalous": risk >= 30,
        "reasons": reasons,
        "risk_score": risk,
        "user": user,
        "checked_at": datetime.utcnow().isoformat(),
    }


def get_user_baseline(user: str) -> dict:
    b = _baseline.get(user, {})
    return {
        "user": user,
        "total_events": b.get("total", 0),
        "active_hours": dict(b.get("hours", {})),
        "known_ips": list(b.get("ips", {}).keys()),
        "first_seen": datetime.utcfromtimestamp(b["first_seen"]).isoformat() if b.get("first_seen") else None,
        "last_seen": datetime.utcfromtimestamp(b["last_seen"]).isoformat() if b.get("last_seen") else None,
    }


def get_all_baselines() -> list:
    return [get_user_baseline(u) for u in _baseline]
