"""
Live Threat Intelligence Feed
-------------------------------
Auto-pulls IOCs from public threat feeds and caches them.
Checks IPs/domains/hashes against known malicious indicators.

Feeds used (free, no key required):
  - URLhaus (malicious URLs)
  - EmergingThreats blocklist (IPs)
  - abuse.ch (malware hashes)

Optional (key required):
  - AbuseIPDB
  - VirusTotal
"""

import os
import re
import time
import logging
import requests
from datetime import datetime, timedelta

log = logging.getLogger(__name__)

_CACHE: dict = {}           # {indicator: {type, severity, source, last_checked}}
_BLOCKLIST_IPS: set = set()
_BLOCKLIST_URLS: set = set()
_last_refresh: float = 0
_REFRESH_INTERVAL = 3600    # refresh every hour

ABUSEIPDB_KEY  = os.getenv('ABUSEIPDB_API_KEY', '')
VIRUSTOTAL_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')


# ── Feed refreshers ───────────────────────────────────────────────────────────

def _refresh_emerging_threats():
    """Pull EmergingThreats compromised IP list."""
    try:
        url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        r = requests.get(url, timeout=10)
        ips = {line.strip() for line in r.text.splitlines()
               if line.strip() and not line.startswith('#')}
        _BLOCKLIST_IPS.update(ips)
        log.info(f"EmergingThreats: loaded {len(ips)} IPs")
    except Exception as e:
        log.warning(f"EmergingThreats feed failed: {e}")


def _refresh_urlhaus():
    """Pull URLhaus malicious URL list."""
    try:
        url = "https://urlhaus.abuse.ch/downloads/text/"
        r = requests.get(url, timeout=10)
        urls = {line.strip() for line in r.text.splitlines()
                if line.strip() and not line.startswith('#')}
        _BLOCKLIST_URLS.update(urls)
        log.info(f"URLhaus: loaded {len(urls)} URLs")
    except Exception as e:
        log.warning(f"URLhaus feed failed: {e}")


def refresh_feeds():
    """Refresh all public threat feeds in background thread."""
    global _last_refresh
    now = time.time()
    if now - _last_refresh < _REFRESH_INTERVAL:
        return
    _last_refresh = now

    import threading
    def _refresh():
        log.info("Refreshing threat feeds (background)...")
        _refresh_emerging_threats()
        _refresh_urlhaus()

    t = threading.Thread(target=_refresh, daemon=True)
    t.start()


# ── Indicator lookup ──────────────────────────────────────────────────────────

def _check_abuseipdb(ip: str) -> dict | None:
    if not ABUSEIPDB_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=5
        )
        d = r.json().get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        if score > 20:
            return {"severity": "High" if score > 75 else "Medium",
                    "source": "AbuseIPDB", "score": score,
                    "country": d.get("countryCode"), "isp": d.get("isp")}
    except Exception as e:
        log.warning(f"AbuseIPDB lookup failed: {e}")
    return None


def _check_virustotal(indicator: str, itype: str = "ip") -> dict | None:
    if not VIRUSTOTAL_KEY:
        return None
    try:
        endpoint = {"ip": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
                    "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
                    "hash": f"https://www.virustotal.com/api/v3/files/{indicator}"}.get(itype)
        if not endpoint:
            return None
        r = requests.get(endpoint,
                         headers={"x-apikey": VIRUSTOTAL_KEY},
                         timeout=5)
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        if malicious > 0:
            return {"severity": "Critical" if malicious > 5 else "High",
                    "source": "VirusTotal", "malicious_engines": malicious}
    except Exception as e:
        log.warning(f"VirusTotal lookup failed: {e}")
    return None


def check_indicator(indicator: str) -> dict:
    """
    Check if an IP, domain, or hash is malicious.
    Returns: {malicious: bool, severity, source, details}
    """
    refresh_feeds()

    # Check local blocklists first (fast, no API call)
    if indicator in _BLOCKLIST_IPS:
        return {"malicious": True, "severity": "High",
                "source": "EmergingThreats", "indicator": indicator}
    if indicator in _BLOCKLIST_URLS:
        return {"malicious": True, "severity": "High",
                "source": "URLhaus", "indicator": indicator}

    # Check cache
    if indicator in _CACHE:
        cached = _CACHE[indicator]
        if time.time() - cached.get("ts", 0) < 86400:  # 24h cache
            return cached

    # Live API checks
    result = None
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
        result = _check_abuseipdb(indicator) or _check_virustotal(indicator, "ip")
    elif re.match(r'^[a-f0-9]{32,64}$', indicator, re.I):
        result = _check_virustotal(indicator, "hash")
    else:
        result = _check_virustotal(indicator, "domain")

    if result:
        result.update({"malicious": True, "indicator": indicator, "ts": time.time()})
        _CACHE[indicator] = result
        return result

    return {"malicious": False, "indicator": indicator, "source": "clean"}


def scan_log_for_iocs(log_text: str) -> list:
    """Extract all IPs from a log line and check them."""
    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', log_text)
    results = []
    for ip in set(ips):
        # Skip private/loopback IPs
        if ip.startswith(('10.', '192.168.', '172.', '127.', '0.')):
            continue
        result = check_indicator(ip)
        if result.get("malicious"):
            results.append(result)
    return results


def get_blocklist_stats() -> dict:
    return {
        "blocked_ips": len(_BLOCKLIST_IPS),
        "blocked_urls": len(_BLOCKLIST_URLS),
        "cached_indicators": len(_CACHE),
        "last_refresh": datetime.utcfromtimestamp(_last_refresh).isoformat() if _last_refresh else None,
    }
