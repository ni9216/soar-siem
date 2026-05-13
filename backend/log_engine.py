from services.severity_engine import severity_score
from services.anomaly_engine import detect_anomaly
from services.correlation_engine import correlate
from datetime import datetime


def process_log(log: str, source_ip: str = "unknown"):

    # Normalize log
    clean_log = log.strip()

    # Run security engines
    severity = severity_score(clean_log)
    anomaly = detect_anomaly(clean_log)
    category = correlate(clean_log)

    # Build unified security event
    event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": source_ip,
        "log": clean_log,

        "severity": severity,
        "anomaly": anomaly,
        "category": category,

        "risk_flag": "HIGH" if severity in ["High", "Critical"] or anomaly == "anomaly" else "LOW"
    }

    return event