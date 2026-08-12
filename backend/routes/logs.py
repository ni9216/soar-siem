from flask import Blueprint, request, jsonify
from datetime import datetime
from flask_jwt_extended import jwt_required
import html
import re

from models import db, Incident
from services.severity_engine import severity_score
from services.ml_models import full_analysis
from services.mitre_mapping import map_to_mitre
from services.soar_engine import auto_response

logs_bp = Blueprint("logs", __name__)

def sanitize_log_input(log_text):
    """
    Sanitize log input to prevent injection attacks
    """
    if not isinstance(log_text, str):
        log_text = str(log_text)
    
    # Limit log size to 10KB
    if len(log_text) > 10240:
        log_text = log_text[:10240]
    
    # Escape HTML special characters
    log_text = html.escape(log_text)
    
    # Remove potentially dangerous characters but keep readable log format
    log_text = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', log_text)
    
    return log_text.strip()

@logs_bp.route("/logs", methods=["POST"])
@jwt_required()
def ingest_log():

    from app import kafka_producer, es, KAFKA_ENABLED, ES_ENABLED, socketio

    data = request.get_json()

    if not data or "log" not in data:
        return jsonify({"error": "log field required"}), 400

    log = data["log"]
    
    # Sanitize input
    try:
        log = sanitize_log_input(log)
    except Exception as e:
        return jsonify({"error": "Invalid log format", "details": str(e)}), 400
    
    if not log:
        return jsonify({"error": "Log content cannot be empty"}), 400

    try:
        severity = severity_score(log)
        ml = full_analysis(log)
        anomaly = ml['anomaly']
        mitre_id = map_to_mitre(log)
    except Exception as e:
        return jsonify({"error": "Error processing log", "details": str(e)}), 500

    # Run correlation engine — detect multi-step attack chains
    attack_chains = []
    try:
        from services.correlation_engine import check_attack_chains
        attack_chains = check_attack_chains(log)
        if attack_chains:
            severity = attack_chains[0]["severity"]  # escalate severity if chain detected
            mitre_id = attack_chains[0].get("mitre", mitre_id)
    except Exception as e:
        print(f"Warning: Correlation engine failed: {e}")

    # Check IPs in log against live threat feeds
    ioc_hits = []
    try:
        from services.threat_feed_auto import scan_log_for_iocs
        ioc_hits = scan_log_for_iocs(log)
        if ioc_hits and severity == 'Low':
            severity = 'High'   # escalate if known malicious IP
    except Exception as e:
        print(f"Warning: Threat feed scan failed: {e}")

    # Send to Kafka if enabled
    if KAFKA_ENABLED and kafka_producer:
        try:
            kafka_producer.send('soc-logs', {'log': log, 'severity': severity, 'anomaly': anomaly, 'mitre_id': mitre_id})
        except Exception as e:
            print(f"Warning: Failed to send to Kafka: {e}")

    # Build enriched title
    title_parts = [f"LOG [{anomaly}]"]
    if attack_chains:
        title_parts.append(f"CHAIN: {attack_chains[0]['chain']}")
    if ioc_hits:
        title_parts.append(f"MALICIOUS IP: {ioc_hits[0]['indicator']}")

    try:
        incident = Incident(
            title=" | ".join(title_parts),
            severity=severity,
            details=log,
            time=datetime.now().strftime("%H:%M:%S"),
            mitre_attack_id=mitre_id
        )
        db.session.add(incident)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error saving incident", "details": str(e)}), 500

    # Run matching playbooks
    try:
        from routes.playbooks import run_playbook_for_incident
        run_playbook_for_incident(incident)
    except Exception as e:
        print(f"Warning: Playbook execution failed: {e}")

    # Trigger SOAR if critical/high
    if severity in ['Critical', 'High']:
        try:
            auto_response.delay(incident.id, severity)
        except Exception as e:
            print(f"Warning: Failed to trigger SOAR: {e}")

    # Index in Elasticsearch if enabled
    if ES_ENABLED and es:
        try:
            es.index(index='soc-logs', document={
                'id': incident.id,
                'log': log,
                'severity': severity,
                'anomaly': anomaly,
                'mitre_id': mitre_id,
                'timestamp': incident.timestamp.isoformat()
            })
        except Exception as e:
            print(f"Warning: Failed to index in Elasticsearch: {e}")

    try:
        socketio.emit("new_incident", {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "details": incident.details,
            "time": incident.time,
            "mitre_attack_id": mitre_id
        })
    except Exception as e:
        print(f"Warning: Failed to emit socket event: {e}")

    return jsonify({
        "status": "ok",
        "severity": severity,
        "anomaly": anomaly,
        "mitre_id": mitre_id
    })