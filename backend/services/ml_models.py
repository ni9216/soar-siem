"""
Extended ML Models
------------------
- Network anomaly detection (port scans, connection spikes)
- User behavior analysis (login patterns, access anomalies)
- Combined scoring for better accuracy
"""

import os
import pickle
import numpy as np
import re
from sklearn.ensemble import IsolationForest

MODELS_DIR = os.path.dirname(os.path.abspath(__file__))

_models = {}

# ── Feature extractors ────────────────────────────────────

def _log_features(text: str) -> list:
    """General log features."""
    t = text.lower()
    return [
        len(text),
        t.count('error'), t.count('fail'), t.count('attack'),
        t.count('scan'), t.count('malware'), t.count('ransomware'),
        t.count('login'), t.count('sql'), t.count('inject'),
        sum(1 for w in ['admin', 'root', 'sudo'] if w in t),
        sum(c.isupper() for c in text) / max(len(text), 1),
    ]


def _network_features(text: str) -> list:
    """Network-specific features."""
    t = text.lower()
    # Extract port numbers
    ports = re.findall(r'\bport[:\s]+(\d+)', t)
    port_count = len(ports)
    high_port = any(int(p) > 1024 for p in ports) if ports else False
    well_known = any(int(p) in [22, 23, 80, 443, 445, 3389] for p in ports) if ports else False

    # Extract IPs
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
    unique_ips = len(set(ips))

    return [
        port_count,
        int(high_port),
        int(well_known),
        unique_ips,
        t.count('connection'), t.count('packet'), t.count('traffic'),
        t.count('firewall'), t.count('blocked'), t.count('allowed'),
        int('nmap' in t or 'masscan' in t or 'zmap' in t),
        int('syn' in t or 'rst' in t or 'fin' in t),
    ]


def _user_behavior_features(text: str) -> list:
    """User behavior-specific features."""
    t = text.lower()
    return [
        t.count('login'), t.count('logout'), t.count('failed'),
        t.count('password'), t.count('auth'), t.count('permission'),
        t.count('denied'), t.count('access'), t.count('sudo'),
        int('after hours' in t or 'unusual time' in t),
        int('multiple' in t or 'brute' in t or 'repeat' in t),
        int('new device' in t or 'unknown ip' in t or 'first time' in t),
    ]


# ── Model loading ─────────────────────────────────────────

def _load_or_train(name: str, feature_fn, normal_logs: list) -> IsolationForest:
    path = os.path.join(MODELS_DIR, '..', f'{name}_model.pkl')
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return pickle.load(f)

    X = np.array([feature_fn(log) for log in normal_logs])
    model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
    model.fit(X)
    with open(path, 'wb') as f:
        pickle.dump(model, f)
    return model


_NORMAL_LOGS = [
    "User login successful from 192.168.1.1",
    "Database connection established on port 5432",
    "File uploaded successfully",
    "Service started on port 8080",
    "Scheduled task executed",
    "Health check passed",
    "Certificate renewed",
    "User session expired",
    "Cache cleared",
    "Report generated",
]

_NORMAL_NETWORK = [
    "Connection on port 80 from 10.0.0.1",
    "HTTPS traffic on port 443",
    "DNS query resolved successfully",
    "Firewall allowed outbound port 443",
    "Load balancer connection port 8080",
    "Database port 5432 connection established",
    "Packet received from 192.168.1.100",
    "Connection closed gracefully",
]

_NORMAL_USER = [
    "User admin login successful",
    "User logout from dashboard",
    "Password changed successfully",
    "Access granted to /api/incidents",
    "User session started",
    "Profile updated successfully",
    "User permissions verified",
    "Auth token refreshed",
]


def _get_model(name):
    if name not in _models:
        if name == 'log':
            _models[name] = _load_or_train('anomaly', _log_features, _NORMAL_LOGS)
        elif name == 'network':
            _models[name] = _load_or_train('network', _network_features, _NORMAL_NETWORK)
        elif name == 'user':
            _models[name] = _load_or_train('user_behavior', _user_behavior_features, _NORMAL_USER)
    return _models[name]


# ── Public API ────────────────────────────────────────────

def detect_anomaly(text: str) -> str:
    """General log anomaly detection."""
    try:
        model = _get_model('log')
        features = np.array([_log_features(text)])
        return 'anomaly' if model.predict(features)[0] == -1 else 'normal'
    except Exception:
        return 'normal'


def detect_network_anomaly(text: str) -> str:
    """Network-specific anomaly detection."""
    try:
        model = _get_model('network')
        features = np.array([_network_features(text)])
        return 'anomaly' if model.predict(features)[0] == -1 else 'normal'
    except Exception:
        return 'normal'


def detect_user_anomaly(text: str) -> str:
    """User behavior anomaly detection."""
    try:
        model = _get_model('user')
        features = np.array([_user_behavior_features(text)])
        return 'anomaly' if model.predict(features)[0] == -1 else 'normal'
    except Exception:
        return 'normal'


def full_analysis(text: str) -> dict:
    """Run all 3 models and return combined result."""
    log_result     = detect_anomaly(text)
    network_result = detect_network_anomaly(text)
    user_result    = detect_user_anomaly(text)

    anomaly_count = sum(1 for r in [log_result, network_result, user_result] if r == 'anomaly')
    combined = 'anomaly' if anomaly_count >= 2 else log_result

    return {
        'anomaly':         combined,
        'log_anomaly':     log_result,
        'network_anomaly': network_result,
        'user_anomaly':    user_result,
    }


def retrain_all():
    """Delete all saved models to force retraining on next call."""
    _models.clear()
    for name in ['anomaly', 'network', 'user_behavior']:
        path = os.path.join(MODELS_DIR, '..', f'{name}_model.pkl')
        if os.path.exists(path):
            os.remove(path)
