from flask import Blueprint, request, jsonify
from datetime import datetime
from flask_jwt_extended import jwt_required

from models import db, Incident
from services.severity_engine import severity_score
from services.anomaly_engine import detect_anomaly
from services.mitre_mapping import map_to_mitre
from services.soar_engine import auto_response

logs_bp = Blueprint("logs", __name__)

@logs_bp.route("/logs", methods=["POST"])
@jwt_required()
def ingest_log():

    from app import kafka_producer, es, KAFKA_ENABLED, ES_ENABLED, socketio

    data = request.get_json()

    if not data or "log" not in data:
        return jsonify({"error": "log field required"}), 400

    log = data["log"]

    severity = severity_score(log)
    anomaly = detect_anomaly(log)
    mitre_id = map_to_mitre(log)

    # Send to Kafka if enabled
    if KAFKA_ENABLED and kafka_producer:
        kafka_producer.send('soc-logs', {'log': log, 'severity': severity, 'anomaly': anomaly, 'mitre_id': mitre_id})

    incident = Incident(
        title=f"LOG [{anomaly}]",
        severity=severity,
        details=log,
        time=datetime.now().strftime("%H:%M:%S"),
        mitre_attack_id=mitre_id
    )

    db.session.add(incident)
    db.session.commit()

    # Trigger SOAR if critical/high
    if severity in ['Critical', 'High']:
        auto_response.delay(incident.id, severity)

    # Index in Elasticsearch if enabled
    if ES_ENABLED and es:
        es.index(index='soc-logs', document={
            'id': incident.id,
            'log': log,
            'severity': severity,
            'anomaly': anomaly,
            'mitre_id': mitre_id,
            'timestamp': incident.timestamp.isoformat()
        })

    socketio.emit("new_incident", {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "details": incident.details,
        "time": incident.time,
        "mitre_attack_id": mitre_id
    })

    return jsonify({
        "status": "ok",
        "severity": severity,
        "anomaly": anomaly,
        "mitre_id": mitre_id
    })