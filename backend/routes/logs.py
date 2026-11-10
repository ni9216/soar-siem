from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from flask_jwt_extended import jwt_required
import html
import hashlib
import re

from models import AlertGroup, DetectionRule, SecuritySetting, db, Incident
from services.audit import record_audit
from services.severity_engine import severity_score
from services.ml_models import full_analysis
from services.mitre_mapping import map_to_mitre
from services.incident_workflow import append_incident_timeline, incident_sla_deadline

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

def process_log(data, source_name='analyst_api'):
    from app import kafka_producer, es, KAFKA_ENABLED, ES_ENABLED, socketio

    if not data or "log" not in data:
        return jsonify({"error": "log field required"}), 400

    log = data["log"]
    
    # Sanitize input
    try:
        log = sanitize_log_input(log)
    except Exception as e:
        print(f"Log format error: {e}")  # Log for debugging
        return jsonify({"error": "Invalid log format"}), 400
    
    if not log:
        return jsonify({"error": "Log content cannot be empty"}), 400

    try:
        severity = severity_score(log)
        ml = full_analysis(log)
        anomaly = ml['anomaly']
        mitre_id = map_to_mitre(log)
    except Exception as e:
        print(f"Log processing error: {e}")  # Log for debugging
        return jsonify({"error": "Error processing log"}), 500

    matched_rules = [rule for rule in DetectionRule.query.filter_by(enabled=True).all() if rule.pattern.casefold() in log.casefold()]
    severity_order = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
    for rule in matched_rules:
        if severity_order.get(rule.severity, 0) > severity_order.get(severity, 0):
            severity = rule.severity
        if rule.mitre_attack_id:
            mitre_id = rule.mitre_attack_id

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
    if matched_rules:
        title_parts.append(f"RULE: {matched_rules[0].name}")

    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log)
    grouping_value = f"{mitre_id or 'unmapped'}|{ip_match.group(0) if ip_match else 'no-ip'}|{severity}"
    grouping_key = hashlib.sha256(grouping_value.encode()).hexdigest()
    group = AlertGroup.query.filter_by(grouping_key=grouping_key).first()

    dedup_setting = SecuritySetting.query.get('alert_dedup_window_minutes')
    try:
        dedup_window_minutes = int(dedup_setting.value) if dedup_setting else 5
    except ValueError:
        from flask import current_app
        current_app.logger.error("Invalid alert_dedup_window_minutes setting; using 5 minutes")
        dedup_window_minutes = 5

    now = datetime.utcnow()
    if group and group.status != 'closed' and dedup_window_minutes > 0:
        duplicate = Incident.query.filter_by(alert_group_id=group.id, details=log).filter(
            Incident.timestamp >= now - timedelta(minutes=dedup_window_minutes),
            Incident.status.notin_({'resolved', 'closed'}),
        ).order_by(Incident.timestamp.desc()).first()
        if duplicate:
            group.incident_count += 1
            group.suppressed_count += 1
            group.last_seen = now
            db.session.commit()
            record_audit('system', 'alert.deduplicated', f'incident/{duplicate.id}', details={
                'alert_group_id': group.id,
                'suppressed_count': group.suppressed_count,
            })
            return jsonify({
                "status": "ok",
                "severity": severity,
                "anomaly": anomaly,
                "mitre_id": mitre_id,
                "alert_group_id": group.id,
                "incident_id": duplicate.id,
                "deduplicated": True,
            })

    try:
        incident = Incident(
            title=" | ".join(title_parts),
            severity=severity,
            details=log,
            time=datetime.now().strftime("%H:%M:%S"),
            mitre_attack_id=mitre_id,
            sla_due_at=incident_sla_deadline(severity),
        )
        db.session.add(incident)
        db.session.flush()
        append_incident_timeline(incident, 'system', 'incident_created', {'source': source_name})
        if group is None:
            group = AlertGroup(
                grouping_key=grouping_key,
                title=incident.title,
                severity=severity,
                mitre_attack_id=mitre_id,
                incident_count=0,
            )
            db.session.add(group)
            db.session.flush()
        group.incident_count += 1
        group.status = 'open'
        group.last_seen = datetime.utcnow()
        incident.alert_group_id = group.id
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Incident save error: {e}")  # Log for debugging
        return jsonify({"error": "Error saving incident"}), 500

    # Run matching playbooks
    try:
        from routes.playbooks import run_playbook_for_incident
        run_playbook_for_incident(incident)
    except Exception as e:
        print(f"Warning: Playbook execution failed: {e}")

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

    record_audit('system', 'log.ingested', f'incident/{incident.id}', details={
        'alert_group_id': incident.alert_group_id,
        'source': source_name,
    })

    return jsonify({
        "status": "ok",
        "incident_id": incident.id,
        "severity": severity,
        "anomaly": anomaly,
        "mitre_id": mitre_id,
        "alert_group_id": incident.alert_group_id,
    })


@logs_bp.route("/logs", methods=["POST"])
@jwt_required()
def ingest_log():
    return process_log(request.get_json(silent=True), 'analyst_api')


@logs_bp.route("/ml/evaluation", methods=["GET"])
@jwt_required()
def get_ml_evaluation():
    from services.ml_evaluation import evaluate_models

    return jsonify(evaluate_models())